// What Infrastructure may ask, and how the agent does it. Infrastructure is not trusted here (ADR 0031): every job
// is checked before anything connects, the script is the one built into the agent, and certificates are always for
// the openasy principal, so a compromised Infrastructure cannot run commands of its own on any host.
import { readFileSync } from "node:fs";
import { parseFacts, type Facts } from "./facts.ts";
import { runScript, scanHostKey, SshError, type Credential, type Endpoint, type SshFailure } from "./ssh.ts";

export const COLLECT_SCRIPT = readFileSync(new URL("./collect.sh", import.meta.url), "utf8");

export interface Job {
  id: string;
  hostId: string;
  action: "collect" | "host-key";
  target: Endpoint & { auth: "certificate" | "key"; containers: boolean };
  jump: Endpoint | null;
}

export type Result =
  | { jobId: string; hostId: string; ok: true; facts: Facts }
  | { jobId: string; hostId: string; ok: true; hostKeys: string[] }
  | { jobId: string; hostId: string; ok: false; error: { kind: SshFailure | "invalid-job"; message: string }; hostKeys?: string[] };

// The same rules Infrastructure applies, checked again: nothing ssh could read as an option.
const ADDRESS = /^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$|^\[[0-9a-fA-F:]+\]$/;
const USER = /^[a-z_][a-z0-9_-]{0,31}$/;
const HOST_KEY = /^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/]+={0,2}$/;

function endpoint(v: unknown, what: string): Endpoint {
  const e = v as Partial<Endpoint> | null;
  if (!e || typeof e !== "object") throw new Error(`${what} is missing`);
  if (typeof e.address !== "string" || !ADDRESS.test(e.address)) throw new Error(`${what}: address is not a host name or IP address`);
  if (typeof e.port !== "number" || !Number.isInteger(e.port) || e.port < 1 || e.port > 65535) throw new Error(`${what}: port is not 1 to 65535`);
  if (typeof e.user !== "string" || !USER.test(e.user)) throw new Error(`${what}: user is not a Unix account name`);
  if (!Array.isArray(e.hostKeys) || e.hostKeys.length > 8 || e.hostKeys.some((k) => typeof k !== "string" || !HOST_KEY.test(k))) throw new Error(`${what}: host keys are not OpenSSH public keys`);
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
  if (typeof t!.containers !== "boolean") throw new Error("target: containers is true or false");
  const jump = j.jump == null ? null : endpoint(j.jump, "jump host");
  if (jump && !jump.hostKeys.length) throw new Error("jump host: its key must be pinned");
  return { id: j.id, hostId: j.hostId, action: j.action, target: { ...target, auth: t!.auth, containers: t!.containers }, jump };
}

export interface Transport {
  runScript: typeof runScript;
  scanHostKey: typeof scanHostKey;
}

export async function runJob(raw: unknown, keys: { caPrivateKey: string; keyPrivateKey: string }, transport: Transport = { runScript, scanHostKey }): Promise<Result> {
  let job: Job;
  try {
    job = checkJob(raw);
  } catch (err) {
    const r = raw as { id?: unknown; hostId?: unknown } | null;
    return { jobId: String(r?.id ?? ""), hostId: String(r?.hostId ?? ""), ok: false, error: { kind: "invalid-job", message: (err as Error).message } };
  }
  const cred: Credential = job.target.auth === "certificate" ? { mode: "certificate", caPrivateKey: keys.caPrivateKey } : { mode: "key", privateKey: keys.keyPrivateKey };
  const base = { jobId: job.id, hostId: job.hostId };
  try {
    if (job.action === "host-key") return { ...base, ok: true, hostKeys: await transport.scanHostKey(job.target, cred, { jump: job.jump ?? undefined }) };
    const out = await transport.runScript(job.target, cred, `${job.target.containers ? "OPENASY_CONTAINERS=1\n" : ""}${COLLECT_SCRIPT}`, { jump: job.jump ?? undefined });
    return { ...base, ok: true, facts: parseFacts(out, { containers: job.target.containers }) };
  } catch (err) {
    const e = err instanceof SshError ? err : new SshError("error", err instanceof Error ? err.message : String(err));
    // A changed key: say which key the host presents now, so an admin can compare it.
    const hostKeys = e.kind === "host-key-changed" ? await transport.scanHostKey(job.target, cred, { jump: job.jump ?? undefined }).catch(() => undefined) : undefined;
    return { ...base, ok: false, error: { kind: e.kind, message: e.message }, ...(hostKeys && { hostKeys }) };
  }
}
