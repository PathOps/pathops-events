// Invalidations (Decision 0063): what changed, never its new state.

export const BUILD_CHANGED = "BUILD_CHANGED";
export const DELIVERY_CHANGED = "DELIVERY_CHANGED";
export const INBOX_CHANGED = "INBOX_CHANGED";
// APPLICATION_CHANGED: the Application itself (created, its provisioning);
// it names no resource.
export const APPLICATION_CHANGED = "APPLICATION_CHANGED";
export const TYPES = [BUILD_CHANGED, DELIVERY_CHANGED, INBOX_CHANGED, APPLICATION_CHANGED] as const;

// Invalidation is what a browser receives: its type, the Application and the
// resource (a Build's, DeliveryRun's or Inbox message's id; absent when the
// type has none) and when it happened.
export interface Invalidation {
  type: (typeof TYPES)[number];
  applicationId: string;
  resourceId?: string;
  occurredAt: string;
}

// Person is a signed-in person: the Cell Dex's issuer and subject.
export interface Person {
  issuer: string;
  subject: string;
}

// Published is an invalidation as the Tenant CP publishes it: the browser's
// event and the person who may receive it (never sent to a browser).
export interface Published {
  invalidation: Invalidation;
  recipient: Person;
}

export const MAX_EVENT_BYTES = 4096;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const FIELDS = new Set(["type", "applicationId", "resourceId", "occurredAt", "recipient"]);

export class InvalidEvent extends Error {}

// parse validates a published body exactly (unknown fields refused) for the
// Cell's issuer.
export function parse(body: unknown, issuer: string, now: Date): Published {
  if (typeof body !== "object" || body === null || Array.isArray(body)) throw new InvalidEvent("not an object");
  const b = body as Record<string, unknown>;
  for (const k of Object.keys(b)) if (!FIELDS.has(k)) throw new InvalidEvent(`unknown field ${k}`);
  const r = b.recipient as Record<string, unknown> | undefined;
  if (typeof r !== "object" || r === null || Object.keys(r).some((k) => k !== "issuer" && k !== "subject"))
    throw new InvalidEvent("recipient is missing or malformed");
  const type = b.type;
  const resourceId = b.resourceId ?? "";
  const occurred = typeof b.occurredAt === "string" && RFC3339.test(b.occurredAt) ? new Date(b.occurredAt) : null;
  if (typeof type !== "string" || !(TYPES as readonly string[]).includes(type)) throw new InvalidEvent("unknown type");
  if (typeof b.applicationId !== "string" || !UUID.test(b.applicationId)) throw new InvalidEvent("applicationId is not a UUID");
  if (typeof resourceId !== "string" || (resourceId !== "" && !UUID.test(resourceId))) throw new InvalidEvent("resourceId is not a UUID");
  if (resourceId !== "" && type === APPLICATION_CHANGED) throw new InvalidEvent("resourceId is not allowed");
  if (resourceId === "" && type !== INBOX_CHANGED && type !== APPLICATION_CHANGED) throw new InvalidEvent("resourceId is required");
  if (!occurred || isNaN(occurred.getTime()) || occurred.getTime() > now.getTime() + 5 * 60_000)
    throw new InvalidEvent("occurredAt is missing or in the future");
  if (r.issuer !== issuer) throw new InvalidEvent("the recipient is not of the Cell's Dex");
  if (typeof r.subject !== "string" || r.subject === "" || r.subject.length > 512)
    throw new InvalidEvent("recipient.subject is missing or too long");
  const invalidation: Invalidation = {
    type: type as Invalidation["type"],
    applicationId: b.applicationId,
    ...(resourceId ? { resourceId } : {}),
    occurredAt: occurred.toISOString(),
  };
  return { invalidation, recipient: { issuer: r.issuer, subject: r.subject } };
}
