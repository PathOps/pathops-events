import { createServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK, type JWTPayload } from "jose";
import { io as connectClient, type Socket as ClientSocket } from "socket.io-client";
import { httpsFetch } from "../src/auth/https-fetch.js";
import { HumanTokenVerifier } from "../src/auth/human-token-verifier.js";
import { ReviewUnavailable, Unauthenticated } from "../src/auth/workload-token-verifier.js";
import { internalServer } from "../src/http/internal-server.js";
import { publicServer, type PublicServer } from "../src/http/public-server.js";
import { jsonLogger, type Logger } from "../src/log.js";

export const UI_AUDIENCE = "pathops-ui";
export const UI_ORIGIN = "https://control-plane-acme.demo.pathops.io";
export const TCP_TOKEN = "tcp-token";
export const TCP = "system:serviceaccount:pathops-system:tenant-control-plane";

export interface Key {
  kid: string;
  privateKey: CryptoKey;
  jwk: JWK;
}

export async function newKey(kid: string): Promise<Key> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  return { kid, privateKey, jwk: { ...(await exportJWK(publicKey)), kid, alg: "RS256", use: "sig" } };
}

export function listenOn(server: HttpServer): Promise<string> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

// FakeDex: discovery and JWKS of a Cell's Dex; its key can rotate; it can be
// down or announce another issuer; it counts fetches.
export class FakeDex {
  url = "";
  key!: Key;
  published: Key[] = [];
  down = false;
  announce: string | null = null;
  fetches = { discovery: 0, jwks: 0 };
  private server = createServer((req, res) => {
    if (this.down) {
      res.writeHead(503).end();
      return;
    }
    if (req.url === "/.well-known/openid-configuration") {
      this.fetches.discovery++;
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ issuer: this.announce ?? this.url, jwks_uri: this.url + "/keys" }));
    } else if (req.url === "/keys") {
      this.fetches.jwks++;
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ keys: this.published.map((k) => k.jwk) }));
    } else res.writeHead(404).end();
  });

  static async start(): Promise<FakeDex> {
    const d = new FakeDex();
    d.url = await listenOn(d.server);
    d.key = await newKey("k1");
    d.published = [d.key];
    return d;
  }

  rotate(k: Key, keepOld: boolean) {
    this.published = keepOld ? [k, this.key] : [k];
    this.key = k;
  }

  claims(subject: string, over: JWTPayload = {}): JWTPayload {
    const now = Math.floor(Date.now() / 1000);
    return { iss: this.url, sub: subject, aud: UI_AUDIENCE, iat: now, exp: now + 300, ...over };
  }

  async mint(claims: JWTPayload, opts: { key?: Key; typ?: string; kid?: string | null } = {}): Promise<string> {
    const key = opts.key ?? this.key;
    const header: Record<string, string> = { alg: "RS256" };
    if (opts.kid !== null) header.kid = opts.kid ?? key.kid;
    if (opts.typ) header.typ = opts.typ;
    return new SignJWT(claims).setProtectedHeader(header as { alg: string }).sign(key.privateKey);
  }

  token(subject: string, over: JWTPayload = {}): Promise<string> {
    return this.mint(this.claims(subject, over));
  }

  verifier(now?: () => Date): HumanTokenVerifier {
    return new HumanTokenVerifier(this.url, UI_AUDIENCE, httpsFetch({ allowHttp: true }), now);
  }

  close() {
    this.server.close();
  }
}

// publishers accepts exactly TCP_TOKEN, and is unavailable for "down".
export const publishers = {
  async verify(token: string) {
    if (token === TCP_TOKEN) return TCP;
    if (token === "down") throw new ReviewUnavailable("down");
    throw new Unauthenticated();
  },
};

// A log a test reads.
export function memoryLog(): Logger & { lines: string[]; text(): string } {
  const lines: string[] = [];
  return { ...jsonLogger((l) => lines.push(l)), lines, text: () => lines.join("\n") };
}

export interface Env {
  dex: FakeDex;
  pub: PublicServer;
  pubURL: string;
  intURL: string;
  log: ReturnType<typeof memoryLog>;
  clients: ClientSocket[];
  close(): Promise<void>;
}

// startEnv: pathops-events (plain HTTP in tests) with the fake Dex as the
// issuer of PathOps tokens.
export async function startEnv(opts: { pingIntervalMs?: number; pingTimeoutMs?: number } = {}): Promise<Env> {
  const dex = await FakeDex.start();
  const log = memoryLog();
  const pub = publicServer({ allowedOrigin: UI_ORIGIN, people: dex.verifier(), log, ...opts });
  const internal = internalServer({ io: pub.io, publishers, issuer: dex.url, log });
  const pubURL = await listenOn(pub.server as HttpServer);
  const intURL = await listenOn(internal as HttpServer);
  const clients: ClientSocket[] = [];
  return {
    dex,
    pub,
    pubURL,
    intURL,
    log,
    clients,
    async close() {
      clients.forEach((c) => c.close());
      await new Promise<void>((r) => pub.io.close(() => r()));
      internal.closeAllConnections();
      await new Promise<void>((r) => internal.close(() => r()));
      dex.close();
    },
  };
}

export interface ClientOptions {
  auth?: Record<string, unknown>;
  origin?: string | null;
  transports?: ("polling" | "websocket")[];
  reconnection?: boolean;
}

// client: the official socket.io-client, with the browser's Origin header.
export function client(env: Env, o: ClientOptions = {}): ClientSocket {
  const origin = o.origin === undefined ? UI_ORIGIN : o.origin;
  const c = connectClient(env.pubURL, {
    auth: o.auth,
    extraHeaders: origin ? { Origin: origin } : {},
    reconnection: o.reconnection ?? false,
    forceNew: true,
    ...(o.transports ? { transports: o.transports } : {}),
  });
  env.clients.push(c);
  return c;
}

// outcome: "connected" or the connect_error message.
export function outcome(c: ClientSocket, ms = 5000): Promise<string> {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve("timeout"), ms);
    c.once("connect", () => {
      clearTimeout(t);
      resolve("connected");
    });
    c.once("connect_error", (e: Error) => {
      clearTimeout(t);
      resolve(e.message);
    });
  });
}

// next resolves with the next event of name (null after ms).
export function next<T = unknown>(c: ClientSocket, name: string, ms = 2000): Promise<T | null> {
  return new Promise((resolve) => {
    const t = setTimeout(() => {
      c.off(name, on);
      resolve(null);
    }, ms);
    const on = (v: T) => {
      clearTimeout(t);
      resolve(v);
    };
    c.once(name, on);
  });
}

export async function publish(env: Env, token: string | null, body: unknown, contentType = "application/json") {
  const r = await fetch(env.intURL + "/internal/v1/events", {
    method: "POST",
    headers: { "content-type": contentType, ...(token !== null ? { authorization: `Bearer ${token}` } : {}) },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  const text = await r.text();
  let json: Record<string, unknown> = {};
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    // not JSON
  }
  return { status: r.status, body: json };
}

export const APP_A = "11111111-1111-4111-8111-111111111111";
export const APP_B = "22222222-2222-4222-8222-222222222222";
export const BUILD_A = "33333333-3333-4333-8333-333333333333";
export const BUILD_A2 = "44444444-4444-4444-8444-444444444444";

export function event(env: Env, type: string, app: string, resource: string | undefined, subject: string): Record<string, unknown> {
  return {
    type,
    applicationId: app,
    ...(resource !== undefined ? { resourceId: resource } : {}),
    occurredAt: new Date().toISOString(),
    recipient: { issuer: env.dex.url, subject },
  };
}

export async function until(cond: () => boolean, ms = 5000, what = "condition"): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

export function connections(env: Env): number {
  return env.pub.io.of("/").sockets.size;
}
