import type { Server } from "socket.io";
import { type Invalidation, type Person } from "./events.js";

// Fan-out (Decision 0063, v1: one replica, in memory, no broker, no replay):
// every connection joins its person's room; an invalidation names the person
// who may read what changed (the Application's owner, as the Tenant CP
// decided) and is emitted to that room only, never broadcast. Nothing is kept:
// an invalidation with no connection is gone, and a browser that reconnects
// reads the current state from REST again.

export const EVENT_INVALIDATE = "invalidate";
export const MAX_CONNECTIONS = 1024;
export const MAX_PER_PERSON = 16;

export function room(p: Person): string {
  return `person:${JSON.stringify([p.issuer, p.subject])}`;
}

// admits reports whether p may open one more connection.
export function admits(io: Server, p: Person): boolean {
  return io.of("/").sockets.size < MAX_CONNECTIONS && (io.of("/").adapter.rooms.get(room(p))?.size ?? 0) < MAX_PER_PERSON;
}

// publish emits inv to p's connections and returns how many there are.
export function publish(io: Server, p: Person, inv: Invalidation): number {
  const n = io.of("/").adapter.rooms.get(room(p))?.size ?? 0;
  if (n > 0) io.to(room(p)).emit(EVENT_INVALIDATE, inv);
  return n;
}
