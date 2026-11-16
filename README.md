# pathops-events

The live-update channel of a PathOps Cell (Decision 0063): a small Go service
that holds the browsers' Server-Sent Events streams and fans out
**invalidations** that the Tenant Control Plane publishes after it commits a
change. It is not a source of truth and keeps no domain state: REST (the Tenant
Control Plane's read model) stays authoritative, and a browser that receives an
invalidation refetches the affected view.

```text
Tenant CP replica(s)
   | EventPublisher (after COMMIT)
   | HTTPS on the Kubernetes Service (Cell CA), short-lived ServiceAccount token
   v
pathops-events  POST /internal/v1/events      (internal listener :9443)
   | in-memory fan-out, filtered by person
   v
Browser         GET /api/v1/events (SSE)      (public listener :8443,
                https://events-<cell>.<domain>, Dex sign-in)
```

## Events

Invalidations only: what changed, never its new state, logs or a domain DTO.

| type | resourceId |
|---|---|
| `BUILD_CHANGED` | the Build's id |
| `DELIVERY_CHANGED` | the DeliveryRun's id |
| `INBOX_CHANGED` | the Inbox message's id (optional) |

A browser receives each as an unnamed SSE event whose data is

```json
{"type":"BUILD_CHANGED","applicationId":"…","resourceId":"…","occurredAt":"…"}
```

The Tenant Control Plane publishes the same fields plus `recipient` (`issuer`,
`subject`): the person who may read the Application by REST (today its owner).
An invalidation reaches only that person's streams; `recipient` is never sent to
a browser.

Nothing is persisted or replayed: no event ids, no `Last-Event-ID`. A browser
that reconnects reads REST again; an invalidation lost while it was away does
not matter.

## Endpoints

Public listener (`PATHOPS_EVENTS_PUBLIC_ADDRESS`, default `:8443`), behind
Traefik TLS passthrough at `https://events-<cell>.<domain>`:

| | |
|---|---|
| `GET /api/v1/events` | the signed-in person's stream. Without a session: `401` for an EventSource (`Accept: text/event-stream`), otherwise `302` to Dex |
| `GET /api/v1/session` | `200` signed in, `401` not (the PathOps UI checks before it starts a sign-in) |
| `GET /login?return=<url>` | sign in at Dex, then back to `<url>` (the PathOps UI's origin or this host only) |
| `GET /oauth2/callback` | the end of a sign-in |
| `POST /logout` | ends the session (Origin: the PathOps UI or this host) |
| `GET /healthz` | liveness |

Internal listener (`PATHOPS_EVENTS_INTERNAL_ADDRESS`, default `:9443`), on the
Kubernetes Service only (no route):

| | |
|---|---|
| `POST /internal/v1/events` | one invalidation (`202 {"delivered": n}`); `401` for any other caller |
| `GET /healthz` | liveness |

## Authentication

**People.** OpenID Connect Authorization Code with PKCE (S256), `state` and
`nonce`, as the confidential Dex client `pathops-events-web`, the same model as
the Artifact Store: the ID token's signature (Dex's JWKS), issuer, audience,
expiry and nonce are checked; the session is a `__Host-` cookie (`Secure`,
`HttpOnly`, `SameSite=Lax`, 8 hours) sealed with AES-256-GCM under the
installer's session key: the identity and its expiry, unreadable and
unforgeable without the key, so a session outlives a restart of pathops-events
and a browser's stream reconnects without signing in again. A sign-out clears
the cookie and revokes it in the running process. No token appears in a URL or
cookie. The PathOps UI is another origin of the same site: its requests
carry the cookie, and CORS allows that origin, with credentials, and no other. A
stream ends at the first heartbeat after its session does.

**The Tenant Control Plane.** A Kubernetes ServiceAccount token, never Dex: the
Tenant CP's Pod mounts a projected token (the kubelet obtains it from the
TokenRequest API and rotates it) with audience `pathops-events` and a 10-minute
lifetime. pathops-events asks the API server to review it (TokenReview with that
audience) and requires the reviewed username to be exactly
`PATHOPS_EVENTS_PUBLISHER`; it also requires the token's issuer to be the
cluster's ServiceAccount issuer, exactly one audience (`pathops-events`) and a
lifetime of at most `PATHOPS_EVENTS_PUBLISHER_MAX_TTL` (1h). A person's OIDC
token, a token of another ServiceAccount, audience or lifetime is refused.
pathops-events' own ServiceAccount may only create TokenReviews.

A NetworkPolicy (installed with it) admits the internal port from the Tenant CP's
Pods only and the public port from Traefik only; it is defence in depth, not the
authentication.

## TLS

Both listeners serve HTTPS with one Cell CA leaf (the core issues it) whose
names are the public host and the Service's DNS names. The Tenant CP publishes
to `https://pathops-events.pathops-system.svc:9443` and verifies that
certificate against the Cell CA and that name; it never goes out through the
public host. Browsers reach the public host through the Cell's public exposure,
which verifies the same leaf (Traefik passes TLS through by SNI). There is no
mTLS: the client is authenticated by its token.

## Streaming

Each stream starts with `retry: 5000` and a `: connected` comment, then sends a
`: heartbeat` comment every `PATHOPS_EVENTS_HEARTBEAT` (25 s): proxies see
traffic before their idle timeouts, and a write that cannot complete in 10 s ends
a dead connection. Responses carry `X-Accel-Buffering: no` (nginx passes each
event on at once) and `Cache-Control: no-store`. A browser that falls 64
invalidations behind is disconnected (it reconnects and reads REST). Limits: 16
streams per person, 1024 in all.

## Configuration

| Variable | |
|---|---|
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | the Cell CA leaf |
| `PATHOPS_EVENTS_PUBLIC_URL` | `https://events-<cell>.<domain>` |
| `PATHOPS_EVENTS_ALLOWED_ORIGIN` | the PathOps UI, `https://<controlPlane host>` |
| `PATHOPS_EVENTS_OIDC_ISSUER` | the Cell's Dex |
| `PATHOPS_EVENTS_OIDC_CLIENT_ID` | default `pathops-events-web` |
| `PATHOPS_EVENTS_OIDC_CLIENT_SECRET_FILE` | its secret |
| `PATHOPS_EVENTS_OIDC_CA_FILE` | the Cell CA (Dex's certificate) |
| `PATHOPS_EVENTS_SESSION_KEY_FILE` | 64 hex characters: the key that seals session cookies (the installer's) |
| `PATHOPS_EVENTS_AUDIENCE` | default `pathops-events` |
| `PATHOPS_EVENTS_PUBLISHER` | `system:serviceaccount:pathops-system:tenant-control-plane` |
| `PATHOPS_EVENTS_PUBLISHER_ISSUER` | the cluster's ServiceAccount issuer |
| `PATHOPS_EVENTS_PUBLISHER_MAX_TTL` | default `1h` |
| `PATHOPS_EVENTS_KUBERNETES_CA_FILE`, `PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE` | the API server's CA and pathops-events' own projected token (TokenReview) |
| `PATHOPS_EVENTS_HEARTBEAT` | default `25s` (1s to 1m) |

`pathops-cell-bootstrap` installs and reconciles it as a normal Cell component.

## Scale

```text
v1:      one replica, in-memory fan-out
future:  more than one replica -> a shared broker between replicas;
         the Tenant CP's EventPublisher contract and the browser's
         SSE contract do not change
```

No broker is chosen yet (no Redis, NATS or Kafka), and there is no durable event
log: durable operational Events are a separate future capability.

## Development

```sh
go vet ./... && go test -race ./...
```

A tag `vX.Y.Z` publishes `ghcr.io/pathops/pathops-events:vX.Y.Z`
(`.github/workflows/release.yml`); a Cell consumes it by digest.
