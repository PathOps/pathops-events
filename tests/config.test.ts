import { describe, expect, it } from "vitest";
import { duration, load } from "../src/config.js";

const base: Record<string, string> = {
  TLS_CERT_FILE: "/tls/tls.crt",
  TLS_KEY_FILE: "/tls/tls.key",
  PATHOPS_EVENTS_ALLOWED_ORIGIN: "https://control-plane-acme.demo.pathops.io",
  PATHOPS_EVENTS_OIDC_ISSUER: "https://dex-acme.demo.pathops.io",
  PATHOPS_EVENTS_PUBLISHER: "system:serviceaccount:pathops-system:tenant-control-plane",
  PATHOPS_EVENTS_PUBLISHER_ISSUER: "https://kubernetes.default.svc.cluster.local",
  PATHOPS_EVENTS_KUBERNETES_CA_FILE: "/kubernetes/ca.crt",
  PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE: "/kubernetes-token/token",
  KUBERNETES_SERVICE_HOST: "10.96.0.1",
  KUBERNETES_SERVICE_PORT: "443",
};

describe("configuration (the same variables as the Go implementation)", () => {
  it("has the defaults", () => {
    const c = load(base);
    expect(c).toMatchObject({
      publicAddress: { port: 8443 },
      internalAddress: { port: 9443 },
      audience: "pathops-events",
      tokenAudience: "pathops-ui",
      publisherMaxTTL: 3_600_000,
      kubernetesURL: "https://10.96.0.1:443",
    });
  });

  it.each<[string, Record<string, string>]>([
    ["no TLS", { TLS_KEY_FILE: "" }],
    ["same listeners", { PATHOPS_EVENTS_INTERNAL_ADDRESS: ":8443" }],
    ["http origin", { PATHOPS_EVENTS_ALLOWED_ORIGIN: "http://control-plane-acme.demo.pathops.io" }],
    ["origin with a path", { PATHOPS_EVENTS_ALLOWED_ORIGIN: "https://control-plane-acme.demo.pathops.io/x" }],
    ["wildcard origin", { PATHOPS_EVENTS_ALLOWED_ORIGIN: "*" }],
    ["no issuer", { PATHOPS_EVENTS_OIDC_ISSUER: "" }],
    ["publisher not an SA", { PATHOPS_EVENTS_PUBLISHER: "tenant-control-plane" }],
    ["publisher issuer", { PATHOPS_EVENTS_PUBLISHER_ISSUER: "" }],
    ["audiences alike", { PATHOPS_EVENTS_AUDIENCE: "pathops-ui" }],
    ["not in a cluster", { KUBERNETES_SERVICE_HOST: "" }],
    ["no own token", { PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE: "" }],
    ["bad TTL", { PATHOPS_EVENTS_PUBLISHER_MAX_TTL: "soon" }],
    ["bad address", { PATHOPS_EVENTS_PUBLIC_ADDRESS: "8443" }],
  ])("refuses %s", (_name, over) => {
    expect(() => load({ ...base, ...over })).toThrow();
  });

  it("parses Go-style durations", () => {
    expect(duration("1h")).toBe(3_600_000);
    expect(duration("1h30m")).toBe(5_400_000);
    expect(duration("90s")).toBe(90_000);
    expect(duration("")).toBeNull();
    expect(duration("10")).toBeNull();
  });
});
