import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { generateKeyPair, SignJWT, type JWTPayload } from "jose";
import { generate } from "selfsigned";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { httpsFetch, systemRootsPlus } from "../src/auth/https-fetch.js";
import { HumanTokenVerifier, LEEWAY_S, MAX_LENGTH, OPERATION_AUTHORIZATION_TYPE, TokenError } from "../src/auth/human-token-verifier.js";
import { FakeDex, newKey, UI_AUDIENCE } from "./helpers.js";

let dex: FakeDex;
let now: Date;
let v: HumanTokenVerifier;
beforeEach(async () => {
  dex = await FakeDex.start();
  now = new Date();
  v = dex.verifier(() => now);
});
afterEach(() => dex.close());

const s = () => Math.floor(now.getTime() / 1000);

async function reason(raw: unknown): Promise<string> {
  try {
    await v.verify(raw);
    return "accepted";
  } catch (e) {
    if (e instanceof TokenError) return e.reason;
    throw e;
  }
}

describe("the PathOps human token (the Tenant CP's contract)", () => {
  it("a token of the Cell's Dex for the PathOps UI: its person and expiry", async () => {
    const id = await v.verify(await dex.mint(dex.claims("alice", { iat: s(), exp: s() + 300 })));
    expect(id).toEqual({ issuer: dex.url, subject: "alice", expiry: new Date((s() + 300) * 1000) });
  });

  it("an audience list containing the UI's is accepted", async () => {
    expect(await reason(await dex.mint(dex.claims("alice", { aud: ["other", UI_AUDIENCE] })))).toBe("accepted");
  });

  it.each<[string, JWTPayload, string]>([
    ["wrong issuer, valid signature", { iss: "https://dex-globex.demo.pathops.io" }, "issuer_mismatch"],
    ["issuer with a trailing slash", { iss: "ISSUER/" }, "issuer_mismatch"],
    ["wrong audience", { aud: "zot" }, "audience_mismatch"],
    ["expired", { iat: -600, exp: -31 }, "expired"],
    ["nbf in the future", { nbf: 31 }, "not_yet_valid"],
    ["iat in the future", { iat: 31, exp: 300 }, "issued_in_future"],
    ["no subject", { sub: undefined }, "missing_claims"],
    ["no audience", { aud: undefined }, "missing_claims"],
    ["no expiry", { exp: undefined }, "missing_claims"],
    ["no issued-at", { iat: undefined }, "missing_claims"],
    ["no issuer", { iss: undefined }, "missing_claims"],
  ])("refuses %s", async (_name, over, want) => {
    const c = dex.claims("alice");
    for (const [k, val] of Object.entries(over)) {
      if (val === undefined) delete c[k];
      else if (k === "iss" && val === "ISSUER/") c.iss = dex.url + "/";
      else if (typeof val === "number" && ["iat", "exp", "nbf"].includes(k)) c[k] = s() + val;
      else c[k] = val;
    }
    expect(await reason(await dex.mint(c))).toBe(want);
  });

  it(`allows ${LEEWAY_S}s of clock skew on exp, nbf and iat`, async () => {
    expect(await reason(await dex.mint(dex.claims("alice", { iat: s() + 25, exp: s() - 25, nbf: s() + 25 })))).toBe("accepted");
  });

  it("refuses another client of the same Dex (the CLI's, Forgejo's, the Artifact Store's, Events' own)", async () => {
    for (const aud of ["pathops-cli", "forgejo", "pathops-artifact-store-web", "pathops-events-web", "pathops-events"])
      expect(await reason(await dex.mint(dex.claims("alice", { aud })))).toBe("audience_mismatch");
  });

  it("refuses an Operation Authorization Token, even with claims that would pass", async () => {
    const oat = await dex.mint(dex.claims("alice", { pathops_plan: "plan-1" }), { typ: OPERATION_AUTHORIZATION_TYPE });
    expect(await reason(oat)).toBe("malformed");
  });

  it("refuses another key under the same kid, and an unknown kid", async () => {
    const evil = await newKey("k1");
    expect(await reason(await dex.mint(dex.claims("alice"), { key: evil }))).toBe("bad_signature");
    expect(await reason(await dex.mint(dex.claims("alice"), { key: { ...evil, kid: "evil" } }))).toBe("unknown_key");
  });

  it("accepts RS256 only: none, HMAC with the public key, ES256 and RS512 are refused before any key is used", async () => {
    const good = await dex.mint(dex.claims("alice"));
    const [, payload] = good.split(".");
    const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    expect(await reason(`${enc({ alg: "none", kid: "k1" })}.${payload}.`)).not.toBe("accepted");
    const hs = await new SignJWT(dex.claims("alice")).setProtectedHeader({ alg: "HS256", kid: "k1" }).sign(new TextEncoder().encode("public-key"));
    expect(await reason(hs)).toBe("unsupported_algorithm");
    const ec = await generateKeyPair("ES256");
    expect(await reason(await new SignJWT(dex.claims("alice")).setProtectedHeader({ alg: "ES256", kid: "k1" }).sign(ec.privateKey))).toBe("unsupported_algorithm");
    const rs512 = await generateKeyPair("RS512");
    expect(await reason(await new SignJWT(dex.claims("alice")).setProtectedHeader({ alg: "RS512", kid: "k1" }).sign(rs512.privateKey))).toBe("unsupported_algorithm");
  });

  it("refuses tampered, malformed, oversized and kid-less tokens", async () => {
    const good = await dex.mint(dex.claims("alice"));
    const [h, , sig] = good.split(".");
    const tampered = `${h}.${Buffer.from(JSON.stringify({ ...dex.claims("mallory") })).toString("base64url")}.${sig}`;
    expect(await reason(tampered)).toBe("bad_signature");
    for (const raw of ["", "x", "a.b", "a.b.c", "x".repeat(MAX_LENGTH + 1), good + "x", 42, null, undefined, { token: good }])
      expect(await reason(raw)).not.toBe("accepted");
    expect(await reason(await dex.mint(dex.claims("alice"), { kid: null }))).toBe("malformed");
  });

  it("caches the keys: one discovery and one JWKS fetch for many tokens", async () => {
    for (let i = 0; i < 20; i++) expect(await reason(await dex.token("alice"))).toBe("accepted");
    expect(dex.fetches).toEqual({ discovery: 1, jwks: 1 });
  });

  it("a rotated key refreshes the keys once; unknown kids do not refresh in a loop", async () => {
    const old = dex.key;
    expect(await reason(await dex.token("alice"))).toBe("accepted");
    await new Promise((r) => setTimeout(r, 31_000));
    dex.rotate(await newKey("k2"), true);
    now = new Date();
    expect(await reason(await dex.token("alice"))).toBe("accepted");
    expect(await reason(await dex.mint(dex.claims("alice"), { key: old }))).toBe("accepted");
    expect(dex.fetches.jwks).toBe(2);
    const evil = await newKey("unknown");
    for (let i = 0; i < 10; i++) expect(await reason(await dex.mint(dex.claims("alice"), { key: evil }))).toBe("unknown_key");
    expect(dex.fetches.jwks).toBe(2);
  }, 40_000);

  it("Dex down: the token is not judged (unavailable); back up, it is", async () => {
    dex.down = true;
    expect(await reason(await dex.token("alice"))).toBe("issuer_keys_unavailable");
    dex.down = false;
    expect(await reason(await dex.token("alice"))).toBe("accepted");
  });

  it("a discovery that names another issuer is not used", async () => {
    dex.announce = "https://dex-globex.demo.pathops.io";
    expect(await reason(await dex.token("alice"))).toBe("issuer_keys_unavailable");
  });
});

describe("TLS to Dex", () => {
  it("is verified: the system roots alone refuse a Cell-CA Dex; with its CA it is trusted", async () => {
    const pems = await generate([{ name: "commonName", value: "127.0.0.1" }], {
      keySize: 2048,
      extensions: [{ name: "subjectAltName", altNames: [{ type: 7, ip: "127.0.0.1" }] }],
    });
    const key = await newKey("k1");
    let url = "";
    const server = createServer({ key: pems.private, cert: pems.cert }, (req, res) => {
      if (req.url === "/.well-known/openid-configuration") res.end(JSON.stringify({ issuer: url, jwks_uri: url + "/keys" }));
      else res.end(JSON.stringify({ keys: [key.jwk] }));
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    url = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const now = Math.floor(Date.now() / 1000);
    const tok = await new SignJWT({ iss: url, sub: "alice", aud: UI_AUDIENCE, iat: now, exp: now + 300 })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .sign(key.privateKey);
    const untrusted = new HumanTokenVerifier(url, UI_AUDIENCE, httpsFetch());
    await expect(untrusted.verify(tok)).rejects.toMatchObject({ reason: "issuer_keys_unavailable" });
    const trusted = new HumanTokenVerifier(url, UI_AUDIENCE, httpsFetch({ ca: systemRootsPlus(pems.cert) }));
    await expect(trusted.verify(tok)).resolves.toMatchObject({ subject: "alice" });
    await expect(new HumanTokenVerifier("http://dex.example", UI_AUDIENCE, httpsFetch()).verify(tok)).rejects.toMatchObject({
      reason: "issuer_keys_unavailable",
    });
    server.close();
  });
});
