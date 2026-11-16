// The runtime configuration, from the environment (the same variables as the
// former Go implementation). Every value is validated at start; an invalid
// configuration stops the process before it listens.

export interface Config {
  // Two HTTPS listeners with the same certificate (the Cell CA leaf of the
  // public name and the Service's names): the public one (browsers, through
  // Traefik) and the internal one (publication by the Tenant CP, on the
  // Service only).
  publicAddress: Address; // PATHOPS_EVENTS_PUBLIC_ADDRESS, default :8443
  internalAddress: Address; // PATHOPS_EVENTS_INTERNAL_ADDRESS, default :9443
  tlsCertFile: string; // TLS_CERT_FILE
  tlsKeyFile: string; // TLS_KEY_FILE

  // People: the PathOps human token (the access token the PathOps UI holds
  // for the Tenant CP), from the Cell's Dex, for the PathOps UI's client.
  allowedOrigin: string; // PATHOPS_EVENTS_ALLOWED_ORIGIN: the PathOps UI, https://<controlPlane host>
  oidcIssuer: string; // PATHOPS_EVENTS_OIDC_ISSUER: the Cell's Dex
  oidcCAFile: string; // PATHOPS_EVENTS_OIDC_CA_FILE: optional roots for Dex (the Cell CA)
  tokenAudience: string; // PATHOPS_EVENTS_TOKEN_AUDIENCE, default pathops-ui

  // Publishers: Kubernetes ServiceAccount tokens, reviewed by the API server
  // (TokenReview with the audience), of exactly the publisher.
  audience: string; // PATHOPS_EVENTS_AUDIENCE, default pathops-events
  publisher: string; // PATHOPS_EVENTS_PUBLISHER: system:serviceaccount:<namespace>:<name>
  publisherIssuer: string; // PATHOPS_EVENTS_PUBLISHER_ISSUER: the cluster's ServiceAccount issuer
  publisherMaxTTL: number; // PATHOPS_EVENTS_PUBLISHER_MAX_TTL (ms), default 1h: a longer-lived token is refused
  // The API server: in-cluster (KUBERNETES_SERVICE_HOST/PORT), with its CA and
  // pathops-events' own projected token (re-read on every review).
  kubernetesURL: string;
  kubernetesCAFile: string; // PATHOPS_EVENTS_KUBERNETES_CA_FILE
  kubernetesTokenFile: string; // PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE
}

export interface Address {
  host?: string;
  port: number;
}

const serviceAccount = /^system:serviceaccount:[a-z0-9]([-a-z0-9]*[a-z0-9])?:[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/;

export class ConfigError extends Error {}

export function load(env: Record<string, string | undefined>): Config {
  const errs: string[] = [];
  const get = (k: string) => env[k] ?? "";
  const or = (k: string, def: string) => get(k) || def;
  const addr = (k: string, def: string): Address => {
    const v = or(k, def);
    const m = /^(?:\[?([^\]]*)\]?)?:(\d{1,5})$/.exec(v);
    const port = m ? Number(m[2]) : NaN;
    if (!m || port < 1 || port > 65535) {
      errs.push(`${k} must be [host]:port`);
      return { port: 0 };
    }
    return m[1] ? { host: m[1], port } : { port };
  };
  const c: Config = {
    publicAddress: addr("PATHOPS_EVENTS_PUBLIC_ADDRESS", ":8443"),
    internalAddress: addr("PATHOPS_EVENTS_INTERNAL_ADDRESS", ":9443"),
    tlsCertFile: get("TLS_CERT_FILE"),
    tlsKeyFile: get("TLS_KEY_FILE"),
    allowedOrigin: get("PATHOPS_EVENTS_ALLOWED_ORIGIN"),
    oidcIssuer: get("PATHOPS_EVENTS_OIDC_ISSUER"),
    oidcCAFile: get("PATHOPS_EVENTS_OIDC_CA_FILE"),
    tokenAudience: or("PATHOPS_EVENTS_TOKEN_AUDIENCE", "pathops-ui"),
    audience: or("PATHOPS_EVENTS_AUDIENCE", "pathops-events"),
    publisher: get("PATHOPS_EVENTS_PUBLISHER"),
    publisherIssuer: get("PATHOPS_EVENTS_PUBLISHER_ISSUER"),
    publisherMaxTTL: 0,
    kubernetesURL: "",
    kubernetesCAFile: get("PATHOPS_EVENTS_KUBERNETES_CA_FILE"),
    kubernetesTokenFile: get("PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE"),
  };
  if (!c.tlsCertFile || !c.tlsKeyFile) errs.push("TLS_CERT_FILE and TLS_KEY_FILE are required (pathops-events serves HTTPS only)");
  if (c.publicAddress.port === c.internalAddress.port && c.publicAddress.host === c.internalAddress.host)
    errs.push("PATHOPS_EVENTS_PUBLIC_ADDRESS and PATHOPS_EVENTS_INTERNAL_ADDRESS must differ");
  if (!isOrigin(c.allowedOrigin)) errs.push("PATHOPS_EVENTS_ALLOWED_ORIGIN must be https://<host> (the PathOps UI)");
  if (!isHttpsURL(c.oidcIssuer)) errs.push("PATHOPS_EVENTS_OIDC_ISSUER must be an https URL");
  if (!serviceAccount.test(c.publisher)) errs.push("PATHOPS_EVENTS_PUBLISHER must be system:serviceaccount:<namespace>:<name>");
  if (!isHttpsURL(c.publisherIssuer))
    errs.push("PATHOPS_EVENTS_PUBLISHER_ISSUER must be an https URL (the cluster's ServiceAccount issuer)");
  // A person's token is never a publisher's, nor the reverse.
  if (c.audience === c.tokenAudience) errs.push("PATHOPS_EVENTS_AUDIENCE must differ from PATHOPS_EVENTS_TOKEN_AUDIENCE");
  const host = get("KUBERNETES_SERVICE_HOST");
  const port = get("KUBERNETES_SERVICE_PORT");
  if (host && port) c.kubernetesURL = `https://${host.includes(":") ? `[${host}]` : host}:${port}`;
  else errs.push("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are required (TokenReview)");
  if (!c.kubernetesCAFile || !c.kubernetesTokenFile)
    errs.push("PATHOPS_EVENTS_KUBERNETES_CA_FILE and PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE are required");
  const ttl = duration(or("PATHOPS_EVENTS_PUBLISHER_MAX_TTL", "1h"));
  if (ttl === null) errs.push(`invalid duration ${JSON.stringify(get("PATHOPS_EVENTS_PUBLISHER_MAX_TTL"))}`);
  else c.publisherMaxTTL = ttl;
  if (errs.length) throw new ConfigError(errs.join("; "));
  return c;
}

function isHttpsURL(v: string): boolean {
  try {
    const u = new URL(v);
    return u.protocol === "https:" && u.host !== "";
  } catch {
    return false;
  }
}

// isOrigin: https://<host>, nothing else.
export function isOrigin(v: string): boolean {
  try {
    const u = new URL(v);
    return u.protocol === "https:" && u.host !== "" && u.origin === v && !u.username && !u.password;
  } catch {
    return false;
  }
}

// duration parses Go-style durations (1h, 30m, 90s, 1h30m) into ms.
export function duration(v: string): number | null {
  const re = /(\d+(?:\.\d+)?)(ms|h|m|s)/y;
  let ms = 0;
  let m: RegExpExecArray | null;
  if (!v) return null;
  while ((m = re.exec(v))) {
    ms += Number(m[1]) * { ms: 1, s: 1_000, m: 60_000, h: 3_600_000 }[m[2] as "ms" | "s" | "m" | "h"];
    if (re.lastIndex === v.length) return ms > 0 ? ms : null;
  }
  return null;
}
