// Redfish over HTTPS, read-only (ADR 0055). The agent only ever sends GET, to paths under /redfish/v1, and writes a
// request on a connection only after the BMC presented the certificate pinned for it, so the password goes to that
// BMC and nowhere else. There is no other method here: a compromised Infrastructure cannot power a server off,
// change a setting or start an update through the agent.
import { Agent, request } from "node:http";
import { isIP } from "node:net";
import type { Duplex } from "node:stream";
import { connect, type PeerCertificate, type TLSSocket } from "node:tls";

export interface BmcEndpoint {
  address: string;
  port: number;
  user: string;
  /** Pinned SHA-256 fingerprints of the BMC's TLS certificate, as Node and openssl print them (AB:CD:...). */
  certificates: string[];
}

export type BmcFailure = "unreachable" | "auth-failed" | "certificate-changed" | "timeout" | "not-redfish" | "error";

export class BmcError extends Error {
  readonly kind: BmcFailure;
  constructor(kind: BmcFailure, message: string) {
    super(message);
    this.kind = kind;
  }
}

export interface Certificate {
  fingerprint: string;
  subject: string;
  issuer: string;
  validTo: string;
}

export type Json = Record<string, unknown>;

/** A Redfish session: GET a path, or null when the BMC does not have it or does not let this account read it. */
export interface Session {
  get(path: string): Promise<Json | null>;
  close(): void;
}

const MAX_BODY = 8 * 1024 * 1024;
/** More than any BMC needs for one collection; a BMC whose links run in circles stops here. */
const MAX_REQUESTS = 600;
// Under the service root, with nothing that climbs out of it, and only the paging a collection links to.
const PATH = /^\/redfish\/v1(\/[A-Za-z0-9._~:@!$&'()*+,;=%-]+)*\/?(\?\$skip=\d+(&\$top=\d+)?|\?\$top=\d+(&\$skip=\d+)?)?$/;

const hostOf = (address: string) => (address.startsWith("[") ? address.slice(1, -1) : address);

function open(e: BmcEndpoint, timeoutMs: number): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const host = hostOf(e.address);
    // BMCs mostly present a certificate of their own making: it is pinned instead of checked against a CA.
    const s = connect({ host, port: e.port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, minVersion: "TLSv1.2" });
    s.setTimeout(timeoutMs, () => s.destroy(new BmcError("timeout", `${e.address}:${e.port} did not answer in ${timeoutMs / 1000} s`)));
    s.once("secureConnect", () => (s.setTimeout(0), resolve(s)));
    s.once("error", (err) => reject(err instanceof BmcError ? err : new BmcError("unreachable", `${e.address}:${e.port}: ${err.message}`)));
  });
}

const dn = (n: PeerCertificate["subject"] | undefined) =>
  Object.entries(n ?? {})
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("+") : v}`)
    .join(", ");

/** The certificate the BMC presents, without signing in. */
export async function bmcCertificate(e: BmcEndpoint, timeoutMs = 15_000): Promise<Certificate> {
  const s = await open(e, timeoutMs);
  try {
    const c = s.getPeerCertificate();
    if (!c?.fingerprint256) throw new BmcError("not-redfish", `${e.address}:${e.port} presents no certificate`);
    return { fingerprint: c.fingerprint256, subject: dn(c.subject), issuer: dn(c.issuer), validTo: new Date(c.valid_to).toISOString() };
  } finally {
    s.destroy();
  }
}

/** Every connection is checked against the pinned certificates before a request is written on it. */
class PinnedAgent extends Agent {
  readonly #e: BmcEndpoint;
  readonly #timeoutMs: number;
  constructor(e: BmcEndpoint, timeoutMs: number) {
    super({ keepAlive: true, maxSockets: 2 });
    this.#e = e;
    this.#timeoutMs = timeoutMs;
  }
  override createConnection(_options: unknown, callback?: (err: Error | null, socket: Duplex) => void): Duplex | null | undefined {
    open(this.#e, this.#timeoutMs).then(
      (s) => {
        const fp = s.getPeerCertificate()?.fingerprint256;
        if (fp && this.#e.certificates.includes(fp)) return callback?.(null, s);
        s.destroy();
        callback?.(
          new BmcError("certificate-changed", `${this.#e.address}:${this.#e.port} presents another certificate (${fp ?? "none"})`),
          undefined as never,
        );
      },
      (err: Error) => callback?.(err, undefined as never),
    );
    return undefined;
  }
}

export function openSession(e: BmcEndpoint, password: string, opts: { timeoutMs?: number; deadlineMs?: number } = {}): Session {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const deadline = Date.now() + (opts.deadlineMs ?? 4 * 60_000);
  if (!e.certificates.length) throw new BmcError("certificate-changed", "no certificate is pinned for this BMC");
  const agent = new PinnedAgent(e, timeoutMs);
  const authorization = `Basic ${Buffer.from(`${e.user}:${password}`).toString("base64")}`;
  let count = 0;
  return {
    close: () => agent.destroy(),
    get(path) {
      if (!PATH.test(path) || path.split(/[/?]/).some((p) => p === ".." || p === "."))
        return Promise.reject(new BmcError("not-redfish", `the BMC links to ${path.slice(0, 200)}, outside /redfish/v1`));
      if (++count > MAX_REQUESTS) return Promise.reject(new BmcError("error", `more than ${MAX_REQUESTS} requests for one collection`));
      if (Date.now() > deadline) return Promise.reject(new BmcError("timeout", "the collection took longer than its deadline"));
      return new Promise((resolve, reject) => {
        const req = request(
          {
            agent,
            host: hostOf(e.address),
            port: e.port,
            path,
            method: "GET",
            headers: { authorization, accept: "application/json", "odata-version": "4.0" },
            timeout: timeoutMs,
          },
          (res) => {
            const chunks: Buffer[] = [];
            let size = 0;
            res.on("data", (c: Buffer) => {
              size += c.length;
              if (size > MAX_BODY) req.destroy(new BmcError("error", `${path} answered more than ${MAX_BODY / 1024 / 1024} MiB`));
              else chunks.push(c);
            });
            res.on("end", () => {
              const status = res.statusCode ?? 0;
              if (status === 401) return reject(new BmcError("auth-failed", `the BMC refused ${e.user}: check the account and its password file`));
              // Not there, or not for a read-only account: what it would have said is listed as not readable.
              if ([403, 404, 405, 501].includes(status)) return resolve(null);
              if (status < 200 || status > 299) return reject(new BmcError("error", `${path} answered ${status}`));
              try {
                const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
                if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
                resolve(body as Json);
              } catch {
                reject(new BmcError("not-redfish", `${path} did not answer with Redfish JSON`));
              }
            });
            res.on("error", reject);
          },
        );
        req.on("timeout", () => req.destroy(new BmcError("timeout", `${path} did not answer in ${timeoutMs / 1000} s`)));
        req.on("error", (err) => reject(err instanceof BmcError ? err : new BmcError("unreachable", `${e.address}:${e.port}: ${err.message}`)));
        req.end();
      });
    },
  };
}
