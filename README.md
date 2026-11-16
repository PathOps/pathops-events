# pathops-events

The live-update channel of a PathOps Cell (Decision 0063): a small Node.js LTS + TypeScript service
that receives transient invalidations from the Tenant Control Plane and fans
them out to authenticated PathOps browsers. It is **not** a source of truth and
keeps no domain state. REST/TCP remains authoritative; clients refetch affected
queries after an invalidation.

The original browser implementation used SSE plus a separate Dex OIDC session.
Decision 0063 supersedes that human-facing transport/auth model with Socket.IO
using the same PathOps bearer token already held by the frontend. The dedicated
`events-<cell>` hostname is retained.

```text
Tenant CP replica(s)
   | EventPublisher (after COMMIT)
   | HTTPS on Kubernetes Service (Cell CA)
   | short-lived ServiceAccount token aud=pathops-events
   v
pathops-events  POST /internal/v1/events
   | one replica, in-memory fan-out
   | official Socket.IO, PathOps bearer token in handshake auth
   v
Browser at https://events-<cell>.<domain>
```

## Events

Invalidations only: what changed, never its new state, logs or a domain DTO.

| type | resourceId |
|---|---|
| `BUILD_CHANGED` | Build id |
| `DELIVERY_CHANGED` | DeliveryRun id |
| `INBOX_CHANGED` | Inbox message id when relevant |
| `APPLICATION_CHANGED` | none: the Application itself (created, its provisioning) |

Typical payload:

```json
{"type":"BUILD_CHANGED","applicationId":"…","resourceId":"…","occurredAt":"…"}
```

The TCP also supplies the recipient identity needed for fan-out authorization;
recipient data is not forwarded to the browser. Nothing is persisted or replayed.
A reconnect causes the frontend to refetch its live REST queries.

## Public browser connection

Canonical host:

```text
https://events-<cell>.<domain>
```

The frontend creates one global Socket.IO connection and passes its existing
PathOps access token in the Socket.IO handshake `auth` payload. Events validates
the explicit PathOps human-token contract (signature, issuer, expiry/not-before
where applicable, audience and subject) and authorizes fan-out by the same
identity used for TCP REST.

There is no Events-specific human OIDC login, callback, browser cookie or session
key. The token is not placed in URLs, query strings,
localStorage or an Events cookie.

Because UI and Events are separate origins, CORS permits only the matching
`https://control-plane-<cell>.<domain>` origin, never `*`.

Socket.IO owns heartbeat/ping-pong and reconnect behavior. On logout the
frontend closes the socket and does not reconnect without a current PathOps
token; after login/token replacement it connects with the current token.

### Implementation stack and protocol

The runtime uses the reference Socket.IO stack rather than a third-party
protocol port:

- Node.js LTS;
- TypeScript;
- Express for HTTP endpoints;
- the official `socket.io` server package;
- the official `socket.io-client` package in the frontend;
- `jose` for human JWT/JWKS verification.

The public listener follows the Socket.IO documentation's standard Express
integration: create the Node HTTP(S) server from the Express app and attach the
Socket.IO `Server` to that same server. The internal M2M listener may use a
separate Express/HTTPS server so `/internal/v1/events` is not exposed on the
public listener.

Socket.IO v5 over Engine.IO v4 (`socket.io-client` 4.x) is served at the normal
`/socket.io/` path on the public listener (default `:8443`):

- transports: use Socket.IO defaults. Engine.IO may begin with HTTP long-polling
  and upgrade to WebSocket when available; PathOps does not force WebSocket-only
  without a measured reason;
- origin: both polling/CORS and WebSocket establishment accept only
  `$PATHOPS_EVENTS_ALLOWED_ORIGIN`; wildcard origins are forbidden;
- authentication: `auth: {token: "<PathOps access token>"}` in the CONNECT
  packet. Refused connections surface as `connect_error`;
- `invalidate` events carry `{type, applicationId, resourceId?, occurredAt}`;
- a connection lasts while its token is valid: the client may emit
  `reauth` `{token}` with a newer token of the same person; if the token expires,
  the server closes the connection and the client reconnects with its current
  token;
- Socket.IO's built-in ping/pong is the only heartbeat. Reconnect/refetch heals
  missed invalidations because REST remains authoritative.

### The human token

The PathOps human token is the access token the PathOps UI obtains from the
Cell's Dex (Authorization Code + PKCE) for its public client `pathops-ui`, the
one it sends to the Tenant CP's REST API. pathops-events verifies the same
contract as the Tenant CP: RS256 with a key of Dex's JWKS (discovery of
`PATHOPS_EVENTS_OIDC_ISSUER`), that issuer exactly, the audience
`PATHOPS_EVENTS_TOKEN_AUDIENCE` (`pathops-ui`), a subject, `exp`, `iat` and
`nbf` with 30 s of leeway; an Operation Authorization Token
(`typ: pathops-oat+jwt`) and the token of any other client of the same Dex (the
CLI's, Forgejo's, the Artifact Store's) are refused. A person receives the
invalidations the Tenant CP addresses to that issuer and subject.

## Internal publication

Internal listener (default `:9443`) remains M2M only:

| endpoint | purpose |
|---|---|
| `POST /internal/v1/events` | publish one invalidation |
| `GET /healthz` | liveness |

TCP publishes to:

```text
https://pathops-events.pathops-system.svc:9443
```

using a projected short-lived Kubernetes ServiceAccount token with audience
`pathops-events`. Events verifies the Cell-CA certificate by Service DNS name,
reviews the workload token and accepts only the expected TCP ServiceAccount.
Human PathOps/Dex tokens are rejected on this endpoint. NetworkPolicy is defense
in depth, not the authentication mechanism.

## TLS

Public realtime traffic is TLS/WSS through the Cell edge. Internal publication
is HTTPS with the Cell CA. There is no `InsecureSkipVerify`; there is no Dex
token exchange for TCP -> Events and no mTLS requirement in v1.

## Configuration

| Variable | |
|---|---|
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | the Cell CA leaf (public host and Service names) |
| `PATHOPS_EVENTS_ALLOWED_ORIGIN` | the PathOps UI, `https://<controlPlane host>` |
| `PATHOPS_EVENTS_OIDC_ISSUER` | the Cell's Dex (the human token's issuer) |
| `PATHOPS_EVENTS_OIDC_CA_FILE` | the Cell CA (Dex's certificate) |
| `PATHOPS_EVENTS_TOKEN_AUDIENCE` | default `pathops-ui` |
| `PATHOPS_EVENTS_AUDIENCE` | the publishers' token audience, default `pathops-events` |
| `PATHOPS_EVENTS_PUBLISHER` | `system:serviceaccount:pathops-system:tenant-control-plane` |
| `PATHOPS_EVENTS_PUBLISHER_ISSUER` | the cluster's ServiceAccount issuer |
| `PATHOPS_EVENTS_PUBLISHER_MAX_TTL` | default `1h` |
| `PATHOPS_EVENTS_KUBERNETES_CA_FILE`, `PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE` | the API server's CA and pathops-events' own projected token (TokenReview) |

## Scale

```text
v1:
  tenant-control-plane replicas = N
  pathops-events replicas        = 1

future, only if Events itself needs horizontal scaling:
  pathops-events replicas > 1
  -> shared pub/sub / Socket.IO adapter
```

No Redis, NATS or Kafka is selected now. TCP scaling does not require a broker:
all TCP replicas publish through the same Events Kubernetes Service to the one
fan-out process.

## Bootstrap/reconcile

`pathops-cell-bootstrap` installs and reconciles Events as a normal Cell
component. Existing Cells converge from the old SSE/OIDC implementation to the
Socket.IO/bearer-token model without a Cell recreate. After the new path is
validated, bootstrap removes the obsolete Events OIDC client/session/cookie/key
configuration while retaining the public Events hostname, internal Service,
Cell-CA TLS and M2M authorization.

## Development

A conventional TypeScript service (Node.js 24 LTS, npm with the lockfile).
`scripts/npm.sh` runs npm in the pinned Node image:

```sh
scripts/npm.sh ci
scripts/npm.sh run check     # typecheck, lint, tests (Vitest, the official socket.io-client)
scripts/npm.sh run build     # dist/
```

```text
src/
  index.ts                     configuration, both listeners, graceful shutdown
  config.ts                    the environment
  log.ts                       JSON lines, never a token
  http/public-server.ts        Express + the official Socket.IO Server on one HTTPS server
  http/internal-server.ts      Express: POST /internal/v1/events, /healthz
  live/socket-server.ts        origin, handshake auth, reauth, token expiry
  live/fanout.ts               one room per person, limits
  live/events.ts               invalidation types and validation
  auth/human-token-verifier.ts the PathOps token (jose: RS256, Dex's JWKS)
  auth/workload-token-verifier.ts  the Tenant CP's ServiceAccount token (TokenReview)
  auth/https-fetch.ts          node:https with the Cell CA (Dex, the API server)
tests/                         the same contracts, through real sockets
```

The image (`Dockerfile`) runs every check in its build stage and ships
distroless Node.js (no shell, no npm), non-root, production dependencies only.

A tag `vX.Y.Z` publishes `ghcr.io/pathops/pathops-events:vX.Y.Z`; a Cell consumes
it by digest.
