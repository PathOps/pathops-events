import {
  createRemoteJWKSet,
  customFetch,
  decodeProtectedHeader,
  errors,
  jwtVerify,
  type JWTVerifyGetKey,
} from "jose";
import type { Fetch } from "./https-fetch.js";

// The PathOps human token (Decision 0063): the access token the PathOps UI
// obtains from the Cell's Dex for its client pathops-ui and sends to the
// Tenant CP's REST API, presented again in the Socket.IO handshake. The same
// contract as the Tenant CP (its internal/auth), ported to jose: a JWT the
// Cell's own Dex signed with RS256 under a key it publishes (OIDC discovery ->
// jwks_uri), the Cell's issuer exactly, the PathOps UI's audience, a subject
// and a current validity window (exp, nbf, iat; 30 s of leeway). An Operation
// Authorization Token, a token of any other client of the same Dex (the
// CLI's, Forgejo's, the Artifact Store's...) or anything else is refused:
// authentication fails closed. The token is never stored or logged.

export const LEEWAY_S = 30;
export const MAX_LENGTH = 8 << 10;
export const OPERATION_AUTHORIZATION_TYPE = "pathops-oat+jwt";
// Keys are used at most this long without a refresh (a key Dex withdrew stops
// verifying); an unknown kid refreshes them at most once in the cooldown.
const KEYS_MAX_AGE_MS = 10 * 60_000;
const REFRESH_COOLDOWN_MS = 30_000;

export type Reason =
  | "issuer_keys_unavailable"
  | "malformed"
  | "unsupported_algorithm"
  | "unknown_key"
  | "bad_signature"
  | "issuer_mismatch"
  | "audience_mismatch"
  | "expired"
  | "not_yet_valid"
  | "issued_in_future"
  | "missing_claims";

export class TokenError extends Error {
  constructor(public readonly reason: Reason) {
    super(reason);
  }
}

// unavailable: the token was not judged (Dex's keys could not be read).
export const isUnavailable = (e: unknown) => e instanceof TokenError && e.reason === "issuer_keys_unavailable";

export interface Identity {
  issuer: string;
  subject: string;
  expiry: Date;
}

const OTHER_ALGORITHMS = new Set(["HS256", "HS384", "HS512", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"]);

export class HumanTokenVerifier {
  private keys: Promise<JWTVerifyGetKey> | null = null;

  constructor(
    private readonly issuer: string,
    private readonly audience: string,
    private readonly fetch: Fetch,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async verify(raw: unknown): Promise<Identity> {
    if (typeof raw !== "string" || raw === "" || raw.length > MAX_LENGTH || raw.split(".").length !== 3) throw new TokenError("malformed");
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(raw);
    } catch {
      throw new TokenError("malformed");
    }
    // Only RS256: "none" and HMAC are never accepted, before any key is used.
    if (header.alg !== "RS256") throw new TokenError(OTHER_ALGORITHMS.has(String(header.alg)) ? "unsupported_algorithm" : "malformed");
    if (!header.kid) throw new TokenError("malformed");
    // An Operation Authorization Token proves a consent; it never authenticates.
    if (header.typ === OPERATION_AUTHORIZATION_TYPE) throw new TokenError("malformed");
    const keys = await this.keySet();
    let payload;
    try {
      ({ payload } = await jwtVerify(raw, keys, {
        algorithms: ["RS256"],
        issuer: this.issuer,
        audience: this.audience,
        clockTolerance: LEEWAY_S,
        currentDate: this.now(),
        requiredClaims: ["iss", "sub", "aud", "exp", "iat"],
      }));
    } catch (e) {
      throw new TokenError(reason(e));
    }
    if (typeof payload.sub !== "string" || payload.sub === "") throw new TokenError("missing_claims");
    if ((payload.iat as number) * 1000 > this.now().getTime() + LEEWAY_S * 1000) throw new TokenError("issued_in_future");
    return { issuer: payload.iss as string, subject: payload.sub, expiry: new Date((payload.exp as number) * 1000) };
  }

  // keySet discovers the issuer's jwks_uri once (the document must name the
  // issuer exactly and an https jwks_uri on its host); a failed discovery is
  // tried again at the next token.
  private keySet(): Promise<JWTVerifyGetKey> {
    this.keys ??= this.discover().catch((e: unknown) => {
      this.keys = null;
      throw e;
    });
    return this.keys;
  }

  private async discover(): Promise<JWTVerifyGetKey> {
    let doc: { issuer?: unknown; jwks_uri?: unknown };
    try {
      const r = await this.fetch(this.issuer + "/.well-known/openid-configuration", { headers: { accept: "application/json" } });
      if (r.status !== 200) throw new Error(`discovery answered ${r.status}`);
      doc = (await r.json()) as typeof doc;
    } catch {
      throw new TokenError("issuer_keys_unavailable");
    }
    let jwks: URL;
    try {
      jwks = new URL(String(doc.jwks_uri));
    } catch {
      throw new TokenError("issuer_keys_unavailable");
    }
    if (doc.issuer !== this.issuer || jwks.host !== new URL(this.issuer).host || jwks.protocol !== new URL(this.issuer).protocol)
      throw new TokenError("issuer_keys_unavailable");
    const set = createRemoteJWKSet(jwks, {
      cacheMaxAge: KEYS_MAX_AGE_MS,
      cooldownDuration: REFRESH_COOLDOWN_MS,
      [customFetch]: this.fetch,
    });
    return set;
  }
}

function reason(e: unknown): Reason {
  if (e instanceof errors.JWTExpired) return "expired";
  if (e instanceof errors.JWTClaimValidationFailed) {
    if (e.reason === "missing") return "missing_claims";
    if (e.claim === "iss") return "issuer_mismatch";
    if (e.claim === "aud") return "audience_mismatch";
    if (e.claim === "nbf") return "not_yet_valid";
    if (e.claim === "iat" && e.reason === "check_failed") return "issued_in_future";
    return "missing_claims";
  }
  if (e instanceof errors.JWKSNoMatchingKey) return "unknown_key";
  if (e instanceof errors.JWSSignatureVerificationFailed) return "bad_signature";
  if (e instanceof errors.JOSEAlgNotAllowed) return "unsupported_algorithm";
  // A key set that cannot be fetched (status, JSON) is a generic JOSEError:
  // the token was not judged.
  if (e instanceof errors.JWKSTimeout || e instanceof errors.JWKSInvalid || (e instanceof errors.JOSEError && e.code === "ERR_JOSE_GENERIC"))
    return "issuer_keys_unavailable";
  if (e instanceof errors.JOSEError) return "malformed";
  // A failed key fetch (network, TLS, status): the token is not judged.
  return "issuer_keys_unavailable";
}
