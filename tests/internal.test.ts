import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MAX_EVENT_BYTES } from "../src/live/events.js";
import { APP_A, BUILD_A, event, publish, startEnv, TCP_TOKEN, UI_ORIGIN, type Env } from "./helpers.js";

let env: Env;
beforeEach(async () => {
  env = await startEnv();
});
afterEach(() => env.close());

describe("publication by the Tenant CP (POST /internal/v1/events)", () => {
  it("is refused without the Tenant CP's ServiceAccount token: none, unknown, a person's PathOps token; 503 when it cannot be reviewed", async () => {
    const ev = event(env, "BUILD_CHANGED", APP_A, BUILD_A, "alice");
    const person = await env.dex.token("alice");
    for (const [name, token] of [["no token", null], ["unknown token", "someone-else"], ["a person's PathOps token", person]] as const)
      expect([name, (await publish(env, token, ev)).status]).toEqual([name, 401]);
    expect((await publish(env, "down", ev)).status).toBe(503);
    expect((await publish(env, TCP_TOKEN, ev)).status).toBe(202);
    expect(env.log.text()).not.toContain(person.split(".")[2]);
  });

  it("is on the internal listener only; Socket.IO is on the public one only", async () => {
    const pub = await fetch(env.pubURL + "/internal/v1/events", {
      method: "POST",
      headers: { authorization: `Bearer ${TCP_TOKEN}`, "content-type": "application/json" },
      body: "{}",
    });
    expect(pub.status).toBe(404);
    const internal = await fetch(env.intURL + "/socket.io/?EIO=4&transport=polling", { headers: { Origin: UI_ORIGIN } });
    expect(internal.status).toBe(404);
  });

  it.each<[string, (m: Record<string, unknown>) => void]>([
    ["unknown type", (m) => (m.type = "APPLICATION_DELETED")],
    ["app not a UUID", (m) => (m.applicationId = "hello")],
    ["resource not a UUID", (m) => (m.resourceId = "../x")],
    ["build without resource", (m) => delete m.resourceId],
    ["application with resource", (m) => (m.type = "APPLICATION_CHANGED")],
    ["future", (m) => (m.occurredAt = new Date(Date.now() + 3_600_000).toISOString())],
    ["no time", (m) => delete m.occurredAt],
    ["recipient of another IdP", (m) => (m.recipient = { issuer: "https://evil", subject: "alice" })],
    ["no recipient", (m) => delete m.recipient],
    ["full domain object", (m) => (m.build = { status: "FAILED", logs: "..." })],
  ])("refuses an invalid invalidation: %s", async (_name, mutate) => {
    const ev = event(env, "BUILD_CHANGED", APP_A, BUILD_A, "alice");
    mutate(ev);
    expect([400, 422]).toContain((await publish(env, TCP_TOKEN, ev)).status);
  });

  it("refuses an oversized body, malformed JSON and another content type", async () => {
    const big = event(env, "BUILD_CHANGED", APP_A, BUILD_A, "a".repeat(MAX_EVENT_BYTES));
    expect((await publish(env, TCP_TOKEN, big)).status).toBe(400);
    expect((await publish(env, TCP_TOKEN, "{not json")).status).toBe(400);
    expect((await publish(env, TCP_TOKEN, JSON.stringify(event(env, "BUILD_CHANGED", APP_A, BUILD_A, "alice")), "text/plain")).status).toBe(415);
  });

  it("answers security headers and serves liveness on both listeners", async () => {
    for (const url of [env.pubURL, env.intURL]) {
      const r = await fetch(url + "/healthz");
      expect(r.status).toBe(200);
      expect(r.headers.get("x-content-type-options")).toBe("nosniff");
      expect(r.headers.get("cache-control")).toBe("no-store");
      expect(r.headers.get("x-powered-by")).toBeNull();
    }
    for (const p of ["/login", "/oauth2/callback", "/api/v1/events", "/api/v1/session"])
      expect([p, (await fetch(env.pubURL + p)).status]).toEqual([p, 404]);
  });
});
