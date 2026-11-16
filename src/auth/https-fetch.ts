import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { rootCertificates } from "node:tls";

// A minimal Fetch (GET and POST with a body) over node:https whose trusted
// roots are exactly what the caller names: the system roots plus a CA (Dex
// behind the Cell CA), or a CA alone (the API server). TLS is always verified;
// redirects are not followed. Plain http is accepted only when allowHttp is
// set (tests).
export type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface FetchOptions {
  ca?: string[]; // PEM roots; undefined: the system roots
  timeoutMs?: number;
  maxBytes?: number;
  allowHttp?: boolean;
}

export function systemRootsPlus(pem: string): string[] {
  return [...rootCertificates, pem];
}

export function httpsFetch(opts: FetchOptions = {}): Fetch {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxBytes = opts.maxBytes ?? 1 << 20;
  return (input, init = {}) =>
    new Promise<Response>((resolve, reject) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      if (url.protocol !== "https:" && !(opts.allowHttp && url.protocol === "http:")) {
        reject(new Error(`refusing ${url.protocol} (https only)`));
        return;
      }
      const headers: Record<string, string> = {};
      new Headers(init.headers).forEach((v, k) => (headers[k] = v));
      const body = typeof init.body === "string" ? init.body : undefined;
      if (body !== undefined) headers["content-length"] = String(Buffer.byteLength(body));
      const req = (url.protocol === "https:" ? httpsRequest : httpRequest)(
        url,
        { method: init.method ?? "GET", headers, ca: opts.ca, timeout: timeoutMs, minVersion: "TLSv1.2" },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on("data", (c: Buffer) => {
            size += c.length;
            if (size > maxBytes) req.destroy(new Error("response too large"));
            else chunks.push(c);
          });
          res.on("end", () => {
            const h = new Headers();
            for (const [k, v] of Object.entries(res.headers)) if (typeof v === "string") h.set(k, v);
            const status = res.statusCode ?? 502;
            const empty = [101, 204, 205, 304].includes(status);
            resolve(new Response(empty ? null : Buffer.concat(chunks), { status, headers: h }));
          });
          res.on("error", reject);
        },
      );
      req.on("timeout", () => req.destroy(new Error(`timeout after ${timeoutMs} ms`)));
      req.on("error", reject);
      if (init.signal) init.signal.addEventListener("abort", () => req.destroy(new Error("aborted")));
      req.end(body);
    });
}
