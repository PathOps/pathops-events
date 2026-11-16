import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer, type ServerOptions } from "node:https";
import express from "express";
import type { Server } from "socket.io";
import { attachLive, type LiveOptions } from "../live/socket-server.js";
import { health, secure } from "./common.js";

// The public listener (browsers, https://events-<cell>.<domain> through
// Traefik): the standard Socket.IO + Express shape, one Node HTTPS server
// created from the Express app with the official Socket.IO Server attached to
// it.
//
//   /socket.io/   Socket.IO (src/live/socket-server.ts)
//   GET /healthz  liveness
//   GET /         what this is
//
// There is no sign-in, session or cookie here, and no publication path.
export interface PublicServer {
  server: HttpServer | HttpsServer;
  io: Server;
}

export function publicServer(o: LiveOptions & { tls?: ServerOptions }): PublicServer {
  const app = express();
  app.disable("x-powered-by");
  app.use(secure);
  app.get("/healthz", health);
  app.get("/", (_req, res) => {
    res.type("text/plain; charset=utf-8").send("PathOps live updates (Socket.IO at /socket.io/).\n");
  });
  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });
  // tls is absent only in tests (plain HTTP).
  const server = o.tls ? createHttpsServer(o.tls, app) : createHttpServer(app);
  return { server, io: attachLive(server, o) };
}
