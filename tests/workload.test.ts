import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { httpsFetch } from "../src/auth/https-fetch.js";
import { MAX_TOKEN_LENGTH, ReviewUnavailable, Unauthenticated, WorkloadTokenVerifier } from "../src/auth/workload-token-verifier.js";
import { listenOn, TCP } from "./helpers.js";

const K8S_ISS = "https://kubernetes.default.svc.cluster.local";
const NOW = new Date(1_800_000_000_000);
const s = (offsetMs: number) => Math.floor((NOW.getTime() + offsetMs) / 1000);

// jwt: an unsigned token with claims (the fake API server decides validity,
// like the real one decides the signature).
function jwt(claims: Record<string, unknown>): string {
  return "eyJhbGciOiJSUzI1NiJ9." + Buffer.from(JSON.stringify(claims)).toString("base64url") + ".c2ln";
}

function good(over: Record<string, unknown> = {}): string {
  const c: Record<string, unknown> = { iss: K8S_ISS, aud: ["pathops-events"], iat: s(-60_000), exp: s(9 * 60_000), sub: TCP };
  for (const [k, v] of Object.entries(over)) {
    if (v === null) delete c[k];
    else c[k] = v;
  }
  return jwt(c);
}

// apiServer answers TokenReviews: a token it knows is authenticated as its
// username with its audiences; every other is not. It counts the reviews.
interface Api {
  users: Record<string, string>;
  audiences?: string[];
  reviews: number;
}

const servers: Server[] = [];
afterEach(() => servers.splice(0).forEach((s) => s.close()));

async function verifier(a: Api, tokenFile?: string): Promise<WorkloadTokenVerifier> {
  const server = createServer((req, res) => {
    a.reviews++;
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.url !== "/apis/authentication.k8s.io/v1/tokenreviews" || req.headers.authorization !== "Bearer own-token") {
        res.writeHead(403).end();
        return;
      }
      const spec = (JSON.parse(body) as { spec: { token: string; audiences: string[] } }).spec;
      const user = a.users[spec.token];
      const ok = user !== undefined && spec.audiences.length === 1 && spec.audiences[0] === "pathops-events";
      res.writeHead(201, { "content-type": "application/json" }).end(
        JSON.stringify({ status: ok ? { authenticated: true, user: { username: user }, audiences: a.audiences } : {} }),
      );
    });
  });
  servers.push(server);
  const url = await listenOn(server);
  const own = tokenFile ?? join(mkdtempSync(join(tmpdir(), "ev-")), "token");
  if (!tokenFile) writeFileSync(own, "own-token\n", { mode: 0o600 });
  return new WorkloadTokenVerifier({
    apiServer: url,
    fetch: httpsFetch({ allowHttp: true }),
    tokenFile: own,
    audience: "pathops-events",
    publisher: TCP,
    issuer: K8S_ISS,
    maxTTLMs: 3_600_000,
    now: () => NOW,
  });
}

describe("the Tenant CP's ServiceAccount token (TokenReview)", () => {
  it("the Tenant CP's short-lived pathops-events token is allowed", async () => {
    const tok = good();
    const v = await verifier({ users: { [tok]: TCP }, audiences: ["pathops-events"], reviews: 0 });
    await expect(v.verify(tok)).resolves.toBe(TCP);
  });

  it.each<[string, string, string, string[]]>([
    ["another ServiceAccount (wrong subject)", good(), "system:serviceaccount:pathops-system:pathops-frontend", ["pathops-events"]],
    ["a ServiceAccount of another namespace", good(), "system:serviceaccount:acme-ci:tenant-control-plane", ["pathops-events"]],
    ["the review names another audience", good(), TCP, [K8S_ISS]],
    ["wrong audience in the token", good({ aud: ["pathops-artifact-store"] }), TCP, ["pathops-events"]],
    ["an additional audience", good({ aud: ["pathops-events", "zot"] }), TCP, ["pathops-events"]],
    ["expired", good({ iat: s(-20 * 60_000), exp: s(-10 * 60_000) }), TCP, ["pathops-events"]],
    ["long-lived (a year)", good({ exp: s(365 * 24 * 3_600_000) }), TCP, ["pathops-events"]],
    ["no expiry", good({ exp: null }), TCP, ["pathops-events"]],
    ["a person's Dex token (another issuer)", good({ iss: "https://dex-acme.demo.pathops.io", aud: "pathops-ui" }), TCP, ["pathops-events"]],
  ])("refuses %s", async (_name, tok, user, aud) => {
    const v = await verifier({ users: { [tok]: user }, audiences: aud, reviews: 0 });
    await expect(v.verify(tok)).rejects.toBeInstanceOf(Unauthenticated);
  });

  it("refuses valid claims the API server does not authenticate (forged, or of a deleted Pod)", async () => {
    const v = await verifier({ users: {}, reviews: 0 });
    await expect(v.verify(good())).rejects.toBeInstanceOf(Unauthenticated);
  });

  it("a malformed token never reaches the API server", async () => {
    const a: Api = { users: {}, reviews: 0 };
    const v = await verifier(a);
    for (const tok of ["", "x", "a.b", "a.!!!.c", "a." + Buffer.from("[1]").toString("base64url") + ".c", "x".repeat(MAX_TOKEN_LENGTH + 1)])
      await expect(v.verify(tok)).rejects.toBeInstanceOf(Unauthenticated);
    expect(a.reviews).toBe(0);
  });

  it("is unavailable (not refused) when its own token or the API server cannot be read", async () => {
    let v = await verifier({ users: {}, reviews: 0 }, join(tmpdir(), "missing-token-" + process.pid));
    await expect(v.verify(good())).rejects.toBeInstanceOf(ReviewUnavailable);
    v = new WorkloadTokenVerifier({ apiServer: "http://127.0.0.1:1", fetch: httpsFetch({ allowHttp: true }), tokenFile: "/etc/hostname",
      audience: "pathops-events", publisher: TCP, issuer: K8S_ISS, maxTTLMs: 3_600_000, now: () => NOW });
    await expect(v.verify(good())).rejects.toBeInstanceOf(ReviewUnavailable);
  });

  it("is https only outside tests", async () => {
    const v = new WorkloadTokenVerifier({ apiServer: "http://127.0.0.1:1", fetch: httpsFetch(), tokenFile: "/etc/hostname",
      audience: "pathops-events", publisher: TCP, issuer: K8S_ISS, maxTTLMs: 3_600_000, now: () => NOW });
    await expect(v.verify(good())).rejects.toBeInstanceOf(ReviewUnavailable);
  });
});
