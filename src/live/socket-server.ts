import type { Server as HttpServer } from "node:http";
import type { Server as HttpsServer } from "node:https";
import { Server, type Socket } from "socket.io";
import { isUnavailable, TokenError, type HumanTokenVerifier } from "../auth/human-token-verifier.js";
import type { Logger } from "../log.js";
import type { Person } from "./events.js";
import { admits, room } from "./fanout.js";

// The browsers' Socket.IO connection (Decision 0063), the official server
// attached to the public HTTPS server, at /socket.io/:
//
//   - transports: Socket.IO's defaults (HTTP long-polling first, upgraded to
//     WebSocket when it can be);
//   - origin: exactly the PathOps UI's, on every Engine.IO request (polling
//     and the WebSocket upgrade: engine middleware, so it does not rest on
//     CORS alone); CORS answers that origin only, never *;
//   - the person's PathOps token in the handshake's auth payload
//     ({token: "<access token>"}), never in a URL, cookie or log; refused with
//     connect_error "unauthorized" (or "unavailable" while Dex's keys cannot
//     be read, "too_many_connections" past the limits);
//   - "invalidate" events {type, applicationId, resourceId?, occurredAt}, to
//     the person's room only;
//   - the connection lasts while its token is valid: "reauth" {token} with a
//     newer token of the same person (ack {ok: true} or {error}) extends it;
//     at the token's expiry the server closes the transport and the client
//     reconnects with its current token;
//   - Socket.IO's own ping/pong; no other heartbeat.

export const EVENT_REAUTH = "reauth";

interface ConnectionData {
  person: Person;
  expiry: number; // ms
  timer?: NodeJS.Timeout;
}

export interface LiveOptions {
  allowedOrigin: string;
  people: Pick<HumanTokenVerifier, "verify">;
  log: Logger;
  pingIntervalMs?: number;
  pingTimeoutMs?: number;
}

export function attachLive(server: HttpServer | HttpsServer, o: LiveOptions): Server {
  const io = new Server(server, {
    serveClient: false,
    cors: { origin: o.allowedOrigin, methods: ["GET", "POST"], credentials: false },
    // A handshake carries one token; nothing larger comes from a browser.
    maxHttpBufferSize: 16 << 10,
    connectTimeout: 10_000,
    ...(o.pingIntervalMs ? { pingInterval: o.pingIntervalMs } : {}),
    ...(o.pingTimeoutMs ? { pingTimeout: o.pingTimeoutMs } : {}),
  });
  // Every Engine.IO request (the polling handshake and its later requests,
  // a direct WebSocket and the polling-to-WebSocket upgrade) must come from
  // the PathOps UI's origin; a request without Origin is refused too.
  io.engine.use((req: { headers: { origin?: string } }, _res: unknown, next: (err?: Error) => void) => {
    next(req.headers.origin === o.allowedOrigin ? undefined : new Error("origin not allowed"));
  });

  io.use((socket, next) => {
    void (async () => {
      const raw: unknown = (socket.handshake.auth as Record<string, unknown> | undefined)?.token;
      try {
        const id = await o.people.verify(raw);
        const person = { issuer: id.issuer, subject: id.subject };
        if (!admits(io, person)) return next(new Error("too_many_connections"));
        (socket.data as ConnectionData).person = person;
        (socket.data as ConnectionData).expiry = id.expiry.getTime();
        next();
      } catch (e) {
        const reason = e instanceof TokenError ? e.reason : "invalid";
        if (isUnavailable(e)) {
          o.log.warn("person not verified", { reason });
          return next(new Error("unavailable"));
        }
        o.log.info("person refused", { reason });
        next(new Error("unauthorized"));
      }
    })();
  });

  io.on("connection", (socket: Socket) => {
    const d = socket.data as ConnectionData;
    void socket.join(room(d.person));
    schedule(socket, o.log);
    socket.on(EVENT_REAUTH, (data: unknown, ack?: unknown) => void reauth(socket, data, ack, o));
    socket.on("disconnect", () => clearTimeout(d.timer));
  });
  return io;
}

// schedule closes the connection at its token's expiry: the transport, so
// socket.io-client reconnects by itself with its current token.
function schedule(socket: Socket, log: Logger) {
  const d = socket.data as ConnectionData;
  clearTimeout(d.timer);
  d.timer = setTimeout(() => {
    log.info("token expired, disconnected");
    socket.conn.close();
  }, Math.max(0, d.expiry - Date.now()));
}

// reauth extends a connection with a newer token of the same person; it
// never changes the person.
async function reauth(socket: Socket, data: unknown, ack: unknown, o: LiveOptions) {
  const reply = (v: { ok: true } | { error: string }) => typeof ack === "function" && (ack as (v: unknown) => void)(v);
  const d = socket.data as ConnectionData;
  const raw = typeof data === "object" && data !== null ? (data as Record<string, unknown>).token : undefined;
  try {
    const id = await o.people.verify(raw);
    if (id.issuer !== d.person.issuer || id.subject !== d.person.subject) {
      o.log.info("reauth refused", { reason: "another_person" });
      return reply({ error: "unauthorized" });
    }
    if (id.expiry.getTime() > d.expiry) {
      d.expiry = id.expiry.getTime();
      schedule(socket, o.log);
    }
    reply({ ok: true });
  } catch (e) {
    o.log.info("reauth refused", { reason: e instanceof TokenError ? e.reason : "invalid" });
    reply({ error: "unauthorized" });
  }
}
