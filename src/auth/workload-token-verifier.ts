import { readFile } from "node:fs/promises";
import type { Fetch } from "./https-fetch.js";

// The publishers of invalidations: the Tenant Control Plane's Kubernetes
// ServiceAccount, with a short-lived token of pathops-events' audience (a
// projected token: the kubelet obtains it from the TokenRequest API and
// rotates it). Dex is not involved (Decision 0063).
//
// The API server reviews the token (TokenReview, with the audience): its
// signature, expiry, audience and, for a Pod-bound token, that the Pod still
// exists. pathops-events then requires, beside the review:
//
//   - the reviewed username to be exactly the expected ServiceAccount;
//   - the reviewed audiences to include the audience;
//   - the token's own claims (read before the review, trusted only because the
//     review accepts the token): the cluster's ServiceAccount issuer, exactly
//     one audience (pathops-events), a lifetime of at most MaxTTL and not
//     expired.
//
// A person's OIDC token (another issuer), a token of another ServiceAccount,
// of another or an additional audience, or a long-lived one is refused.

export const MAX_TOKEN_LENGTH = 8192;

export class Unauthenticated extends Error {
  constructor() {
    super("unauthenticated");
  }
}

export class ReviewUnavailable extends Error {}

export interface WorkloadVerifierOptions {
  apiServer: string; // https://host:port
  fetch: Fetch; // TLS with exactly the cluster CA
  tokenFile: string; // pathops-events' own API token (re-read on every review: the kubelet rotates it)
  audience: string; // pathops-events
  publisher: string; // system:serviceaccount:<namespace>:<name>
  issuer: string; // the cluster's ServiceAccount issuer
  maxTTLMs: number; // the longest token lifetime (exp - iat) accepted
  now?: () => Date;
}

interface TokenReview {
  status?: { authenticated?: boolean; user?: { username?: string }; audiences?: string[] };
}

export class WorkloadTokenVerifier {
  constructor(private readonly o: WorkloadVerifierOptions) {}

  // verify returns the publisher's username when token is its valid token.
  async verify(token: string): Promise<string> {
    if (!token || token.length > MAX_TOKEN_LENGTH) throw new Unauthenticated();
    this.claims(token);
    let own: string;
    try {
      own = (await readFile(this.o.tokenFile, "utf8")).trim();
    } catch (e) {
      throw new ReviewUnavailable(String(e));
    }
    const body = JSON.stringify({
      apiVersion: "authentication.k8s.io/v1",
      kind: "TokenReview",
      spec: { token, audiences: [this.o.audience] },
    });
    let res: Response;
    try {
      res = await this.o.fetch(this.o.apiServer + "/apis/authentication.k8s.io/v1/tokenreviews", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${own}` },
        body,
      });
    } catch (e) {
      throw new ReviewUnavailable(String(e));
    }
    if (res.status !== 201 && res.status !== 200) throw new ReviewUnavailable(`TokenReview answered ${res.status}`);
    let review: TokenReview;
    try {
      review = (await res.json()) as TokenReview;
    } catch (e) {
      throw new ReviewUnavailable(String(e));
    }
    const st = review.status ?? {};
    if (!st.authenticated || !(st.audiences ?? []).includes(this.o.audience) || st.user?.username !== this.o.publisher)
      throw new Unauthenticated();
    return st.user.username;
  }

  // claims checks the token's issuer, audience and lifetime.
  private claims(token: string) {
    const parts = token.split(".");
    if (parts.length !== 3 || !/^[A-Za-z0-9_-]+$/.test(parts[1])) throw new Unauthenticated();
    let c: { iss?: unknown; aud?: unknown; exp?: unknown; iat?: unknown };
    try {
      c = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as typeof c;
    } catch {
      throw new Unauthenticated();
    }
    if (typeof c !== "object" || c === null || !Number.isInteger(c.exp) || !Number.isInteger(c.iat)) throw new Unauthenticated();
    const aud = typeof c.aud === "string" ? [c.aud] : c.aud;
    const now = (this.o.now ?? (() => new Date()))().getTime();
    const exp = (c.exp as number) * 1000;
    const iat = (c.iat as number) * 1000;
    if (
      c.iss !== this.o.issuer ||
      !Array.isArray(aud) ||
      aud.length !== 1 ||
      aud[0] !== this.o.audience ||
      !(now < exp) ||
      exp - iat > this.o.maxTTLMs ||
      !(iat < exp)
    )
      throw new Unauthenticated();
  }
}
