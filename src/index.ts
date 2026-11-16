// pathops-events (Decision 0063): the Cell's live-update channel. Browsers of
// signed-in people hold one Socket.IO connection each, authenticated by the
// PathOps token the UI already holds for the Tenant CP; the Tenant Control
// Plane publishes small invalidations on an internal listener with a
// short-lived ServiceAccount token; each one reaches the connections of the
// person it names. It keeps no domain state: REST stays the source of truth.
// One replica, in memory. The configuration comes from the environment.
import { readFileSync } from "node:fs";
import type { Server as NetServer } from "node:net";
import { httpsFetch, systemRootsPlus } from "./auth/https-fetch.js";
import { HumanTokenVerifier } from "./auth/human-token-verifier.js";
import { WorkloadTokenVerifier } from "./auth/workload-token-verifier.js";
import { ConfigError, load, type Address } from "./config.js";
import { internalServer } from "./http/internal-server.js";
import { publicServer } from "./http/public-server.js";
import { jsonLogger } from "./log.js";

const log = jsonLogger();
const SHUTDOWN_TIMEOUT_MS = 10_000;

function listen(server: NetServer, a: Address): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(a.port, a.host, () => {
      log.info("listening", { addr: `${a.host ?? ""}:${a.port}` });
      resolve();
    });
  });
}

async function main() {
  const cfg = load(process.env);
  const tls = { cert: readFileSync(cfg.tlsCertFile), key: readFileSync(cfg.tlsKeyFile), minVersion: "TLSv1.2" as const };
  const dexRoots = cfg.oidcCAFile ? systemRootsPlus(readFileSync(cfg.oidcCAFile, "utf8")) : undefined;
  const people = new HumanTokenVerifier(cfg.oidcIssuer, cfg.tokenAudience, httpsFetch({ ca: dexRoots }));
  const publishers = new WorkloadTokenVerifier({
    apiServer: cfg.kubernetesURL,
    fetch: httpsFetch({ ca: [readFileSync(cfg.kubernetesCAFile, "utf8")] }),
    tokenFile: cfg.kubernetesTokenFile,
    audience: cfg.audience,
    publisher: cfg.publisher,
    issuer: cfg.publisherIssuer,
    maxTTLMs: cfg.publisherMaxTTL,
  });
  const pub = publicServer({ allowedOrigin: cfg.allowedOrigin, people, log, tls });
  const internal = internalServer({ io: pub.io, publishers, issuer: cfg.oidcIssuer, log, tls });
  log.info("configuration", {
    node: process.version,
    allowedOrigin: cfg.allowedOrigin,
    oidcIssuer: cfg.oidcIssuer,
    tokenAudience: cfg.tokenAudience,
    audience: cfg.audience,
    publisher: cfg.publisher,
    publisherIssuer: cfg.publisherIssuer,
    publisherMaxTtlMs: cfg.publisherMaxTTL,
  });
  await listen(pub.server, cfg.publicAddress);
  await listen(internal, cfg.internalAddress);

  const stop = (signal: string) => {
    // Connections end first (browsers reconnect to the next replica start).
    log.info("shutting down", { signal, connections: pub.io.of("/").sockets.size });
    const force = setTimeout(() => process.exit(0), SHUTDOWN_TIMEOUT_MS);
    force.unref();
    void pub.io.close(() => {
      internal.close(() => process.exit(0));
      internal.closeAllConnections();
    });
  };
  process.once("SIGTERM", () => stop("SIGTERM"));
  process.once("SIGINT", () => stop("SIGINT"));
}

main().catch((e: unknown) => {
  log.error("pathops-events failed", { error: e instanceof ConfigError ? e.message : String(e) });
  process.exit(1);
});
