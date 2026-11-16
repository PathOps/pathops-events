import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { OPERATION_AUTHORIZATION_TYPE } from "../src/auth/human-token-verifier.js";
import { FakeDex, newKey, UI_AUDIENCE } from "./helpers.js";
import {
  APP_A, APP_B, BUILD_A, BUILD_A2, client, connections, event, next, outcome, publish, startEnv, TCP_TOKEN, UI_ORIGIN, until,
  type Env,
} from "./helpers.js";

let env: Env;
let tokens: string[] = [];
beforeEach(async () => {
  env = await startEnv({ pingIntervalMs: 200, pingTimeoutMs: 400 });
  tokens = [];
});
afterEach(async () => {
  // No token ever reaches the log.
  for (const t of tokens) expect(env.log.text()).not.toContain(t.split(".")[2]);
  await env.close();
});

async function tok(subject: string, over = {}): Promise<string> {
  const t = await env.dex.token(subject, over);
  tokens.push(t);
  return t;
}

async function person(subject: string, extra = {}) {
  const c = client(env, { auth: { token: await tok(subject) }, ...extra });
  expect(await outcome(c)).toBe("connected");
  return c;
}

describe("people: the PathOps token in the handshake's auth", () => {
  it("connects with a valid PathOps token and receives its person's invalidations: exactly the four fields", async () => {
    const c = await person("alice");
    await until(() => connections(env) === 1);
    const got = next<Record<string, unknown>>(c, "invalidate");
    const r = await publish(env, TCP_TOKEN, event(env, "BUILD_CHANGED", APP_A, BUILD_A, "alice"));
    expect(r).toEqual({ status: 202, body: { delivered: 1 } });
    const ev = await got;
    expect(Object.keys(ev ?? {}).sort()).toEqual(["applicationId", "occurredAt", "resourceId", "type"]);
    expect(ev).toMatchObject({ type: "BUILD_CHANGED", applicationId: APP_A, resourceId: BUILD_A });
  });

  it("refuses anything but a valid PathOps token at the CONNECT, and leaves nothing behind", async () => {
    const other = await FakeDex.start();
    const now = Math.floor(Date.now() / 1000);
    const good = await tok("alice");
    const [h, , sig] = good.split(".");
    const cases: [string, Record<string, unknown> | undefined][] = [
      ["no auth", undefined],
      ["no token", {}],
      ["empty token", { token: "" }],
      ["not a string", { token: 42 }],
      ["not a JWT", { token: "hello" }],
      ["expired", { token: await tok("alice", { iat: now - 600, exp: now - 60 }) }],
      ["wrong issuer", { token: await tok("alice", { iss: "https://dex-globex.demo.pathops.io" }) }],
      ["another Dex's key", { token: await other.mint(other.claims("alice", { iss: env.dex.url })) }],
      ["the CLI's audience", { token: await tok("alice", { aud: "pathops-cli" }) }],
      ["Events' audience", { token: await tok("alice", { aud: "pathops-events" }) }],
      ["no subject", { token: await env.dex.mint({ ...env.dex.claims("x"), sub: undefined }) }],
      ["not yet valid", { token: await tok("alice", { nbf: now + 60 }) }],
      ["tampered", { token: `${h}.${Buffer.from(JSON.stringify(env.dex.claims("mallory"))).toString("base64url")}.${sig}` }],
      ["operation token", { token: await env.dex.mint(env.dex.claims("alice", { aud: UI_AUDIENCE }), { typ: OPERATION_AUTHORIZATION_TYPE }) }],
      ["in a bearer slot", { Authorization: `Bearer ${good}` }],
    ];
    for (const [name, auth] of cases) {
      const c = client(env, { auth });
      expect([name, await outcome(c)]).toEqual([name, "unauthorized"]);
      c.close();
    }
    await until(() => connections(env) === 0);
    expect(env.log.text()).toContain('"reason":"expired"');
    expect(env.log.text()).toContain('"reason":"audience_mismatch"');
    other.close();
  });

  it("while Dex's keys cannot be read the token is not judged: unavailable", async () => {
    const t = await tok("alice");
    env.dex.down = true;
    expect(await outcome(client(env, { auth: { token: t } }))).toBe("unavailable");
  });
});

describe("origin and transports", () => {
  it("Socket.IO defaults: the polling handshake, then the upgrade to WebSocket; the connection then works", async () => {
    const c = client(env, { auth: { token: await tok("alice") } });
    const upgraded = new Promise<string>((r) => c.io.on("open", () => c.io.engine.once("upgrade", (t: { name: string }) => r(t.name))));
    expect(await outcome(c)).toBe("connected");
    expect(await upgraded).toBe("websocket");
    const got = next<Record<string, unknown>>(c, "invalidate");
    await publish(env, TCP_TOKEN, event(env, "INBOX_CHANGED", APP_A, undefined, "alice"));
    expect(await got).toMatchObject({ type: "INBOX_CHANGED" });
  });

  it("polling alone and WebSocket alone both work (nothing is disabled)", async () => {
    for (const transports of [["polling"], ["websocket"]] as const) {
      const c = client(env, { auth: { token: await tok("alice") }, transports: [...transports] });
      expect(await outcome(c)).toBe("connected");
      expect(c.io.engine.transport.name).toBe(transports[0]);
      c.close();
    }
  });

  it("only the PathOps UI's origin: another, a look-alike, http or none is refused, on polling and on WebSocket", async () => {
    for (const transports of [["polling"], ["websocket"]] as const)
      for (const origin of ["https://evil.example", `${UI_ORIGIN}.evil.example`, UI_ORIGIN.replace("https", "http"), null]) {
        const c = client(env, { auth: { token: await tok("alice") }, origin, transports: [...transports] });
        expect([transports[0], origin, await outcome(c)]).not.toEqual([transports[0], origin, "connected"]);
        c.close();
      }
    expect(connections(env)).toBe(0);
  });

  it("CORS answers the PathOps UI's origin only, never *", async () => {
    const ok = await fetch(`${env.pubURL}/socket.io/?EIO=4&transport=polling`, { headers: { Origin: UI_ORIGIN } });
    expect(ok.status).toBe(200);
    expect(ok.headers.get("access-control-allow-origin")).toBe(UI_ORIGIN);
    const evil = await fetch(`${env.pubURL}/socket.io/?EIO=4&transport=polling`, { headers: { Origin: "https://evil.example" } });
    expect(evil.status).toBeGreaterThanOrEqual(400);
    expect(evil.headers.get("access-control-allow-origin")).not.toBe("*");
    const none = await fetch(`${env.pubURL}/socket.io/?EIO=4&transport=polling`);
    expect(none.status).toBeGreaterThanOrEqual(400);
  });

  it("an upgrade from another origin onto a session opened by the UI's is refused (not only the handshake)", async () => {
    const r = await fetch(`${env.pubURL}/socket.io/?EIO=4&transport=polling`, { headers: { Origin: UI_ORIGIN } });
    const sid = (JSON.parse((await r.text()).slice(1)) as { sid: string }).sid;
    const { WebSocket } = await import("ws");
    const url = `${env.pubURL.replace("http", "ws")}/socket.io/?EIO=4&transport=websocket&sid=${sid}`;
    const status = await new Promise<string>((resolve) => {
      const ws = new WebSocket(url, { headers: { Origin: "https://evil.example" } });
      ws.on("open", () => resolve("open"));
      ws.on("unexpected-response", (_req, res) => resolve(String(res.statusCode)));
      ws.on("error", () => resolve("error"));
    });
    expect(status).not.toBe("open");
  });
});

describe("fan-out", () => {
  it("an invalidation reaches every connection of the person it names and no one else's", async () => {
    const a1 = await person("alice");
    const a2 = await person("alice");
    const b = await person("bob");
    await until(() => connections(env) === 3);
    const got = [next(a1, "invalidate"), next(a2, "invalidate"), next(b, "invalidate", 400)];
    expect(await publish(env, TCP_TOKEN, event(env, "DELIVERY_CHANGED", APP_A, BUILD_A, "alice"))).toEqual({ status: 202, body: { delivered: 2 } });
    const [x1, x2, xb] = await Promise.all(got);
    expect(x1).toMatchObject({ type: "DELIVERY_CHANGED" });
    expect(x2).toMatchObject({ type: "DELIVERY_CHANGED" });
    expect(xb).toBeNull();
    const gb = [next(b, "invalidate"), next(a1, "invalidate", 400)];
    expect(await publish(env, TCP_TOKEN, event(env, "INBOX_CHANGED", APP_B, undefined, "bob"))).toEqual({ status: 202, body: { delivered: 1 } });
    const [yb, ya] = await Promise.all(gb);
    expect(yb).toMatchObject({ type: "INBOX_CHANGED", applicationId: APP_B });
    expect(yb).not.toHaveProperty("resourceId");
    expect(ya).toBeNull();
  });

  it("an Application's own change names no resource", async () => {
    const c = await person("bob");
    const got = next<Record<string, unknown>>(c, "invalidate");
    expect((await publish(env, TCP_TOKEN, event(env, "APPLICATION_CHANGED", APP_B, undefined, "bob"))).body).toEqual({ delivered: 1 });
    expect(await got).toEqual({ type: "APPLICATION_CHANGED", applicationId: APP_B, occurredAt: expect.any(String) });
  });

  it("a browser that leaves (or stops answering pings) is removed; one that comes back is admitted again", async () => {
    let c = await person("alice");
    c.close();
    await until(() => connections(env) === 0);
    expect((await publish(env, TCP_TOKEN, event(env, "BUILD_CHANGED", APP_A, BUILD_A, "alice"))).body).toEqual({ delivered: 0 });
    c = await person("alice", { transports: ["websocket"] });
    // Socket.IO's ping/pong: a peer that stops answering is dropped.
    (c.io.engine as unknown as { _sendPacket: () => void })._sendPacket = () => {}; // no pong
    await until(() => connections(env) === 0, 3000, "the silent peer dropped");
    c = await person("alice");
    await new Promise((r) => setTimeout(r, 1000)); // answering pings: still there
    expect(connections(env)).toBe(1);
    const got = next<Record<string, unknown>>(c, "invalidate");
    await publish(env, TCP_TOKEN, event(env, "BUILD_CHANGED", APP_A, BUILD_A2, "alice"));
    expect(await got).toMatchObject({ resourceId: BUILD_A2 });
  });

  it("limits a person to 16 connections", async () => {
    for (let i = 0; i < 16; i++) await person("alice", { transports: ["websocket"] });
    expect(await outcome(client(env, { auth: { token: await tok("alice") } }))).toBe("too_many_connections");
    expect(await outcome(client(env, { auth: { token: await tok("bob") } }))).toBe("connected");
  });
});

describe("token expiry and reauth", () => {
  const soon = () => ({ exp: Math.floor(Date.now() / 1000) + 2 });

  it("a connection ends at its token's expiry (the transport closes, so the client reconnects by itself)", async () => {
    const c = client(env, { auth: { token: await tok("alice", soon()) } });
    expect(await outcome(c)).toBe("connected");
    const reason = await next<string>(c, "disconnect", 5000);
    expect(reason).toBe("transport close");
    await until(() => connections(env) === 0);
  });

  it("reauth with a newer token of the same person extends it; another person's, expired, forged or malformed ones do not", async () => {
    const c = client(env, { auth: { token: await tok("alice", soon()) } });
    expect(await outcome(c)).toBe("connected");
    const now = Math.floor(Date.now() / 1000);
    const evil = await newKey("k1");
    const refused = [
      await tok("bob"),
      await tok("alice", { iat: now - 600, exp: now - 60 }),
      await tok("alice", { aud: "pathops-cli" }),
      await env.dex.mint(env.dex.claims("alice"), { key: evil }),
      "garbage",
    ];
    for (const t of refused) expect(await c.timeout(2000).emitWithAck("reauth", { token: t })).toEqual({ error: "unauthorized" });
    expect(await c.timeout(2000).emitWithAck("reauth", { token: await tok("alice") })).toEqual({ ok: true });
    await new Promise((r) => setTimeout(r, 3000)); // past the first token's expiry
    expect(c.connected).toBe(true);
    const got = next<Record<string, unknown>>(c, "invalidate");
    expect((await publish(env, TCP_TOKEN, event(env, "BUILD_CHANGED", APP_A, BUILD_A, "alice"))).body).toEqual({ delivered: 1 });
    expect(await got).toMatchObject({ type: "BUILD_CHANGED" });
  });

  it("a refused reauth leaves the connection to end at its token's expiry", async () => {
    const c = client(env, { auth: { token: await tok("alice", soon()) } });
    expect(await outcome(c)).toBe("connected");
    expect(await c.timeout(2000).emitWithAck("reauth", { token: await tok("bob") })).toEqual({ error: "unauthorized" });
    expect(await next<string>(c, "disconnect", 5000)).toBe("transport close");
  });
});

describe("shutdown", () => {
  it("closing the server ends every connection; nothing is admitted after", async () => {
    const c = await person("alice");
    const reason = next<string>(c, "disconnect", 3000);
    await new Promise<void>((r) => env.pub.io.close(() => r()));
    expect(await reason).not.toBeNull();
    expect(connections(env)).toBe(0);
  });
});
