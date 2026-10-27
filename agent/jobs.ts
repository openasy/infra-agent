// What Infrastructure may ask, and how the agent does it. Infrastructure is not trusted here (ADR 0031): every job
// is checked before anything connects, the script is the one built into the agent, and certificates are always for
// the openasy principal, so a compromised Infrastructure cannot run commands of its own on any host. BMCs are read
// with GET requests only, and only from one that presents its pinned certificate (ADR 0055).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { readBmc, type BmcFacts } from "./bmc.ts";
import { parseFacts, type Facts } from "./facts.ts";
import { BmcError, bmcCertificate, openSession, type BmcEndpoint, type BmcFailure, type Certificate, type Session } from "./redfish.ts";
import { runScript, scanHostKey, SshError, type Credential, type Endpoint, type SshFailure } from "./ssh.ts";

export const COLLECT_SCRIPT = readFileSync(new URL("./collect.sh", import.meta.url), "utf8");

export interface Job {
  id: string;
  hostId: string;
  action: "collect" | "host-key";
  /** keyFile: a private key in the agent's key folder, for auth key; without it, the agent's own key. */
  target: Endpoint & { auth: "certificate" | "key"; keyFile?: string; containers: boolean };
  jump: Endpoint | null;
}

/** A BMC to read over Redfish, or whose certificate to fetch. passwordFile is in the agent's key folder. */
export interface BmcJob {
  id: string;
  bmcId: string;
  action: "bmc-collect" | "bmc-certificate";
  target: BmcEndpoint & { passwordFile: string };
}

export type Result =
  | { jobId: string; hostId: string; ok: true; facts: Facts }
  | { jobId: string; hostId: string; ok: true; hostKeys: string[] }
  | { jobId: string; hostId: string; ok: false; error: { kind: SshFailure | "invalid-job"; message: string }; hostKeys?: string[] }
  | { jobId: string; bmcId: string; ok: true; facts: BmcFacts }
  | { jobId: string; bmcId: string; ok: true; certificate: Certificate }
  | { jobId: string; bmcId: string; ok: false; error: { kind: BmcFailure | "invalid-job"; message: string }; certificate?: Certificate };

// The same rules Infrastructure applies, checked again: nothing ssh could read as an option.
const ADDRESS = /^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$|^\[[0-9a-fA-F:]+\]$/;
const USER = /^[a-z_][a-z0-9_-]{0,31}$/;
// A file name in the key folder: no slash, so it never leaves the folder, and no leading dot.
const KEY_FILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const HOST_KEY = /^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/]+={0,2}$/;
const BMC_USER = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/;
const CERTIFICATE = /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/;

function endpoint(v: unknown, what: string): Endpoint {
  const e = v as Partial<Endpoint> | null;
  if (!e || typeof e !== "object") throw new Error(`${what} is missing`);
  if (typeof e.address !== "string" || !ADDRESS.test(e.address)) throw new Error(`${what}: address is not a host name or IP address`);
  if (typeof e.port !== "number" || !Number.isInteger(e.port) || e.port < 1 || e.port > 65535) throw new Error(`${what}: port is not 1 to 65535`);
  if (typeof e.user !== "string" || !USER.test(e.user)) throw new Error(`${what}: user is not a Unix account name`);
  if (!Array.isArray(e.hostKeys) || e.hostKeys.length > 8 || e.hostKeys.some((k) => typeof k !== "string" || !HOST_KEY.test(k)))
    throw new Error(`${what}: host keys are not OpenSSH public keys`);
  return { address: e.address, port: e.port, user: e.user, hostKeys: e.hostKeys };
}

/** Throws when Infrastructure sent something the agent will not do. */
export function checkJob(raw: unknown): Job {
  const j = raw as Partial<Job> | null;
  if (!j || typeof j !== "object" || typeof j.id !== "string" || typeof j.hostId !== "string") throw new Error("a job needs an id and a host id");
  if (j.action !== "collect" && j.action !== "host-key") throw new Error("action is collect or host-key");
  const t = j.target as Job["target"] | undefined;
  const target = endpoint(t, "target");
  if (t!.auth !== "certificate" && t!.auth !== "key") throw new Error("target: auth is certificate or key");
  if (t!.keyFile !== undefined && (typeof t!.keyFile !== "string" || !KEY_FILE.test(t!.keyFile))) throw new Error("target: keyFile is a file name");
  if (t!.keyFile !== undefined && t!.auth !== "key") throw new Error("target: keyFile needs auth key");
  if (typeof t!.containers !== "boolean") throw new Error("target: containers is true or false");
  const jump = j.jump == null ? null : endpoint(j.jump, "jump host");
  if (jump && !jump.hostKeys.length) throw new Error("jump host: its key must be pinned");
  const keyFile = t!.keyFile !== undefined ? { keyFile: t!.keyFile } : {};
  return { id: j.id, hostId: j.hostId, action: j.action, target: { ...target, auth: t!.auth, ...keyFile, containers: t!.containers }, jump };
}

/** Throws when Infrastructure sent a BMC job the agent will not do. */
export function checkBmcJob(raw: unknown): BmcJob {
  const j = raw as Partial<BmcJob> | null;
  if (!j || typeof j !== "object" || typeof j.id !== "string" || typeof j.bmcId !== "string") throw new Error("a job needs an id and a BMC id");
  if (j.action !== "bmc-collect" && j.action !== "bmc-certificate") throw new Error("action is bmc-collect or bmc-certificate");
  const t = j.target as Partial<BmcJob["target"]> | null | undefined;
  if (!t || typeof t !== "object") throw new Error("target is missing");
  if (typeof t.address !== "string" || !ADDRESS.test(t.address)) throw new Error("target: address is not a host name or IP address");
  if (typeof t.port !== "number" || !Number.isInteger(t.port) || t.port < 1 || t.port > 65535) throw new Error("target: port is not 1 to 65535");
  if (typeof t.user !== "string" || !BMC_USER.test(t.user)) throw new Error("target: user is not a BMC account name");
  if (typeof t.passwordFile !== "string" || !KEY_FILE.test(t.passwordFile)) throw new Error("target: passwordFile is a file name");
  if (!Array.isArray(t.certificates) || t.certificates.length > 4 || t.certificates.some((c) => typeof c !== "string" || !CERTIFICATE.test(c)))
    throw new Error("target: certificates are SHA-256 fingerprints");
  // The password is sent only to a BMC whose certificate is pinned.
  if (j.action === "bmc-collect" && !t.certificates.length) throw new Error("target: its certificate must be pinned");
  return {
    id: j.id,
    bmcId: j.bmcId,
    action: j.action,
    target: { address: t.address, port: t.port, user: t.user, passwordFile: t.passwordFile, certificates: t.certificates },
  };
}

/** The certificate, the agent's own key, or a key file the install put in the key folder; what is in it never leaves here. */
function credential(job: Job, keys: { caPrivateKey: string; keyPrivateKey: string }, keyDir: string): Credential {
  if (job.target.auth === "certificate") return { mode: "certificate", caPrivateKey: keys.caPrivateKey };
  if (job.target.keyFile === undefined) return { mode: "key", privateKey: keys.keyPrivateKey };
  let key: string;
  try {
    key = readFileSync(join(keyDir, job.target.keyFile), "utf8");
  } catch {
    throw new Error(`key file ${job.target.keyFile} is not readable in ${keyDir}`);
  }
  if (!/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key.trimStart())) throw new Error(`key file ${job.target.keyFile} is not a private key`);
  // ssh refuses a key file without a final newline, as an editor may save it.
  return { mode: "key", privateKey: key.endsWith("\n") ? key : `${key}\n` };
}

export interface Transport {
  runScript: typeof runScript;
  scanHostKey: typeof scanHostKey;
  bmcCertificate?: typeof bmcCertificate;
  openSession?: (e: BmcEndpoint, password: string) => Session;
}

/** The BMC account's password from the key folder: the file's text without its final newline. */
function password(job: BmcJob, keyDir: string): string {
  let text: string;
  try {
    text = readFileSync(join(keyDir, job.target.passwordFile), "utf8");
  } catch {
    throw new Error(`password file ${job.target.passwordFile} is not readable in ${keyDir}`);
  }
  const p = text.replace(/\r?\n$/, "");
  if (!p || p.length > 256 || /[\r\n]/.test(p)) throw new Error(`password file ${job.target.passwordFile} must hold the password on one line`);
  return p;
}

async function runBmcJob(raw: unknown, transport: Transport, keyDir: string): Promise<Result> {
  let job: BmcJob;
  try {
    job = checkBmcJob(raw);
  } catch (err) {
    const r = raw as { id?: unknown; bmcId?: unknown } | null;
    return { jobId: String(r?.id ?? ""), bmcId: String(r?.bmcId ?? ""), ok: false, error: { kind: "invalid-job", message: (err as Error).message } };
  }
  const base = { jobId: job.id, bmcId: job.bmcId };
  const certificate = transport.bmcCertificate ?? bmcCertificate;
  try {
    if (job.action === "bmc-certificate") return { ...base, ok: true, certificate: await certificate(job.target) };
    let pw: string;
    try {
      pw = password(job, keyDir);
    } catch (err) {
      return { ...base, ok: false, error: { kind: "auth-failed", message: (err as Error).message } };
    }
    const session = (transport.openSession ?? openSession)(job.target, pw);
    try {
      return { ...base, ok: true, facts: await readBmc((path) => session.get(path)) };
    } finally {
      await session.close();
    }
  } catch (err) {
    const e = err instanceof BmcError ? err : new BmcError("error", err instanceof Error ? err.message : String(err));
    // Another certificate: say which one the BMC presents now, so an admin can compare it.
    const now = e.kind === "certificate-changed" ? await certificate(job.target).catch(() => undefined) : undefined;
    return { ...base, ok: false, error: { kind: e.kind, message: e.message }, ...(now && { certificate: now }) };
  }
}

export async function runJob(
  raw: unknown,
  keys: { caPrivateKey: string; keyPrivateKey: string },
  transport: Transport = { runScript, scanHostKey },
  keyDir = process.env.OPENASY_KEYS_DIR ?? "/keys",
): Promise<Result> {
  const action = (raw as { action?: unknown } | null)?.action;
  if (action === "bmc-collect" || action === "bmc-certificate") return runBmcJob(raw, transport, keyDir);
  let job: Job;
  try {
    job = checkJob(raw);
  } catch (err) {
    const r = raw as { id?: unknown; hostId?: unknown } | null;
    return { jobId: String(r?.id ?? ""), hostId: String(r?.hostId ?? ""), ok: false, error: { kind: "invalid-job", message: (err as Error).message } };
  }
  const base = { jobId: job.id, hostId: job.hostId };
  let cred: Credential;
  try {
    cred = credential(job, keys, keyDir);
  } catch (err) {
    return { ...base, ok: false, error: { kind: "auth-failed", message: (err as Error).message } };
  }
  try {
    if (job.action === "host-key") return { ...base, ok: true, hostKeys: await transport.scanHostKey(job.target, cred, { jump: job.jump ?? undefined }) };
    const out = await transport.runScript(job.target, cred, `${job.target.containers ? "OPENASY_CONTAINERS=1\n" : ""}${COLLECT_SCRIPT}`, {
      jump: job.jump ?? undefined,
    });
    return { ...base, ok: true, facts: parseFacts(out, { containers: job.target.containers }) };
  } catch (err) {
    const e = err instanceof SshError ? err : new SshError("error", err instanceof Error ? err.message : String(err));
    // A changed key: say which key the host presents now, so an admin can compare it.
    const hostKeys =
      e.kind === "host-key-changed" ? await transport.scanHostKey(job.target, cred, { jump: job.jump ?? undefined }).catch(() => undefined) : undefined;
    return { ...base, ok: false, error: { kind: e.kind, message: e.message }, ...(hostKeys && { hostKeys }) };
  }
}
