// Redfish over HTTPS, read-only (ADR 0055). The agent reads with GET, to paths under /redfish/v1, and writes a
// request on a connection only after the BMC presented the certificate pinned for it, so the password goes to that
// BMC and nowhere else. The only other requests are its own sign-in and sign-out (ADR 0056): a POST to the BMC's
// session collection and a DELETE of the session that POST made, neither to a path Infrastructure can choose. A
// compromised Infrastructure cannot power a server off, change a setting or start an update through the agent.
import { Agent, request, type IncomingHttpHeaders } from "node:http";
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
  /** Signs out, when it signed in, and closes the connections. */
  close(): Promise<void>;
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
  constructor(e: BmcEndpoint, timeoutMs: number, keepAlive = true) {
    super({ keepAlive, maxSockets: 2 });
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

// Where a BMC keeps its sessions: Redfish puts them under SessionService, iDRAC 8 at /redfish/v1/Sessions.
const SESSIONS = /^\/redfish\/v1(\/SessionService)?\/Sessions$/;
// The one session the agent may DELETE: the one its own sign-in made.
const SESSION = /^\/redfish\/v1(\/SessionService)?\/Sessions\/[A-Za-z0-9._~-]+$/;
// What a connection the BMC closed between two requests says when the next request goes out on it.
const RESET = new Set(["ECONNRESET", "EPIPE"]);
// What Node says when an answer on a kept-alive connection does not start like HTTP: iDRAC 8's web server (Appweb 4.5)
// writes a few bytes past the length it gave, and the next answer on that connection starts with them.
const MALFORMED = /^HPE_/;

interface Answer {
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

interface SignedIn {
  token: string;
  /** The session to DELETE at the end; null when the BMC did not say where it is, and it expires on its own. */
  uri: string | null;
}

export function openSession(e: BmcEndpoint, password: string, opts: { timeoutMs?: number; deadlineMs?: number } = {}): Session {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  // Below the 10 minutes Infrastructure leases a job for, so a slow BMC ends as a timeout and not as a lost job.
  const deadline = Date.now() + (opts.deadlineMs ?? 8 * 60_000);
  if (!e.certificates.length) throw new BmcError("certificate-changed", "no certificate is pinned for this BMC");
  const agent = new PinnedAgent(e, timeoutMs);
  // A connection of its own for each request: the sign-in and sign-out always, so neither is ever sent twice, and every
  // request once the BMC sent something past an answer's end.
  const fresh = new PinnedAgent(e, timeoutMs, false);
  let reuse = true;
  const basic = `Basic ${Buffer.from(`${e.user}:${password}`).toString("base64")}`;
  let count = 0;
  // An iDRAC checks Basic auth again on every request, seconds each; with a session's token a request takes about a
  // second. Signed in once, after the service root; a BMC that gives no token is read with Basic auth (ADR 0056).
  let session: Promise<SignedIn | null> | undefined;

  function send(method: "GET" | "POST" | "DELETE", path: string, headers: Record<string, string>, body?: string, again = false): Promise<Answer> {
    return new Promise((resolve, reject) => {
      let answered = false;
      const req = request(
        {
          agent: reuse && method === "GET" ? agent : fresh,
          host: hostOf(e.address),
          port: e.port,
          path,
          method,
          headers: {
            accept: "application/json",
            "odata-version": "4.0",
            ...headers,
            ...(body !== undefined && { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) }),
          },
          timeout: timeoutMs,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          const done = () => ((answered = true), resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
          // An answer is whole at the length it gave: what Appweb writes past it fails the parser only after that.
          const length = Number(res.headers["content-length"] ?? NaN);
          if (length === 0) done();
          res.on("data", (c: Buffer) => {
            size += c.length;
            if (size > MAX_BODY) req.destroy(new BmcError("error", `${path} answered more than ${MAX_BODY / 1024 / 1024} MiB`));
            else if ((chunks.push(c), size === length)) done();
          });
          res.on("end", done);
          res.on("error", reject);
        },
      );
      req.on("timeout", () => req.destroy(new BmcError("timeout", `${path} did not answer in ${timeoutMs / 1000} s`)));
      req.on("error", (err) => {
        // What the connection says after the whole answer is the next request's business, if it has one.
        if (answered) return;
        if (err instanceof BmcError) return reject(err);
        // The BMC closed a kept-alive connection as this request went out on it, or the answer started with what it
        // wrote past the last one: once more, on a new connection. A sign-in is never sent again.
        const code = (err as NodeJS.ErrnoException).code ?? "";
        if (MALFORMED.test(code)) reuse = false;
        if (!again && method !== "POST" && (RESET.has(code) || MALFORMED.test(code))) return resolve(send(method, path, headers, body, true));
        reject(new BmcError("unreachable", `${e.address}:${e.port}: ${err.message}`));
      });
      req.end(body);
    });
  }

  async function signIn(root: Json | null): Promise<SignedIn | null> {
    const linked = ((root?.Links as Json | undefined)?.Sessions as Json | undefined)?.["@odata.id"];
    const at = typeof linked === "string" && SESSIONS.test(linked) ? linked : "/redfish/v1/SessionService/Sessions";
    count++;
    let r: Answer;
    try {
      r = await send("POST", at, {}, JSON.stringify({ UserName: e.user, Password: password }));
    } catch (err) {
      if (err instanceof BmcError && err.kind === "certificate-changed") throw err;
      return null;
    }
    if (r.status === 401) throw new BmcError("auth-failed", `the BMC refused ${e.user}: check the account and its password file`);
    // The token is what counts: some iDRAC 8 firmware answers 405 and still makes the session.
    const token = r.headers["x-auth-token"];
    if (typeof token !== "string" || !token) return null;
    let uri: string | null = null;
    try {
      const p = new URL(String(r.headers.location ?? ""), "https://bmc").pathname.replace(/\/$/, "");
      if (SESSION.test(p)) uri = p;
    } catch {
      // No usable location: the session times out on the BMC.
    }
    return { token, uri };
  }

  // Started before anything awaits it: a refused sign-in must not end the agent as an unhandled rejection.
  function start(root: Json | null) {
    const p = signIn(root);
    p.catch(() => undefined);
    return p;
  }

  return {
    async close() {
      const s = await session?.catch(() => null);
      if (s?.uri) await send("DELETE", s.uri, { "x-auth-token": s.token }).catch(() => undefined);
      agent.destroy();
      fresh.destroy();
    },
    async get(path) {
      if (!PATH.test(path) || path.split(/[/?]/).some((p) => p === ".." || p === "."))
        throw new BmcError("not-redfish", `the BMC links to ${path.slice(0, 200)}, outside /redfish/v1`);
      if (++count > MAX_REQUESTS) throw new BmcError("error", `more than ${MAX_REQUESTS} requests for one collection`);
      if (Date.now() > deadline) throw new BmcError("timeout", "the collection took longer than its deadline");
      const root = path === "/redfish/v1" && !session;
      if (!root) session ??= start(null);
      const s = root ? null : await session;
      const r = await send("GET", path, s ? { "x-auth-token": s.token } : { authorization: basic });
      if (r.status === 401) throw new BmcError("auth-failed", `the BMC refused ${e.user}: check the account and its password file`);
      // Not there, or not for a read-only account: what it would have said is listed as not readable.
      if ([403, 404, 405, 501].includes(r.status)) return null;
      if (r.status < 200 || r.status > 299) throw new BmcError("error", `${path} answered ${r.status}`);
      let body: Json;
      try {
        const parsed = JSON.parse(r.body.toString("utf8")) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
        body = parsed as Json;
      } catch {
        throw new BmcError("not-redfish", `${path} did not answer with Redfish JSON`);
      }
      if (root) session = start(body);
      return body;
    },
  };
}
