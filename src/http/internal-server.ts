import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer, type ServerOptions } from "node:https";
import express, { type NextFunction, type Request, type Response } from "express";
import type { Server } from "socket.io";
import { ReviewUnavailable, type WorkloadTokenVerifier } from "../auth/workload-token-verifier.js";
import type { Logger } from "../log.js";
import { InvalidEvent, MAX_EVENT_BYTES, parse } from "../live/events.js";
import { publish } from "../live/fanout.js";
import { health, secure } from "./common.js";

// The internal listener (the Tenant Control Plane, on the Kubernetes Service
// only; no route):
//
//   POST /internal/v1/events  one invalidation for one person (202
//                             {delivered: n}), from the expected
//                             ServiceAccount's short-lived token (401
//                             otherwise, 503 while it cannot be reviewed)
//   GET  /healthz             liveness
export interface InternalOptions {
  io: Server;
  publishers: Pick<WorkloadTokenVerifier, "verify">;
  issuer: string; // the Cell Dex's: an invalidation names a person of this issuer
  log: Logger;
  now?: () => Date;
  tls?: ServerOptions;
}

export function internalServer(o: InternalOptions): HttpServer | HttpsServer {
  const app = express();
  app.disable("x-powered-by");
  app.use(secure);
  app.get("/healthz", health);
  app.post("/internal/v1/events", authenticate(o), express.json({ limit: MAX_EVENT_BYTES, strict: true }), (req: Request, res: Response) => {
    let p;
    try {
      p = parse(req.body, o.issuer, (o.now ?? (() => new Date()))());
    } catch (e) {
      if (!(e instanceof InvalidEvent)) throw e;
      res.status(422).json({ error: "invalid_event", reason: e.message });
      return;
    }
    const n = publish(o.io, p.recipient, p.invalidation);
    o.log.info("published", { type: p.invalidation.type, applicationId: p.invalidation.applicationId,
      resourceId: p.invalidation.resourceId ?? "", delivered: n });
    res.status(202).json({ delivered: n });
  });
  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });
  // A body that is not JSON, too large or malformed.
  // (Four parameters: Express's error handler.)
  app.use((_err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    res.status(400).json({ error: "bad_request" });
  });
  return o.tls ? createHttpsServer(o.tls, app) : createHttpServer(app);
}

function authenticate(o: InternalOptions) {
  return (req: Request, res: Response, next: NextFunction) => {
    const h = req.get("authorization") ?? "";
    if (!h.startsWith("Bearer ")) {
      res.status(401).json({ error: "unauthenticated" });
      return;
    }
    o.publishers.verify(h.slice("Bearer ".length).trim()).then(
      () => {
        if (!req.is("application/json")) {
          res.status(415).json({ error: "json_required" });
          return;
        }
        next();
      },
      (e: unknown) => {
        if (e instanceof ReviewUnavailable) {
          o.log.warn("publisher not verified", { error: e.message });
          res.status(503).json({ error: "unavailable" });
          return;
        }
        o.log.info("publisher refused");
        res.status(401).json({ error: "unauthenticated" });
      },
    );
  };
}
