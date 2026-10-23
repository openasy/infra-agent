// SSH with the system's OpenSSH client (ADR 0031): certificates, jump hosts and strict host key checking are
// OpenSSH's own, not reimplemented. Private keys exist only in a 0700 temporary directory for one connection.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ACCOUNT } from "./setup.ts";

export interface Endpoint {
  address: string;
  port: number;
  user: string;
  /** Pinned host keys, "type base64" each. */
  hostKeys: string[];
}

export type Credential = { mode: "certificate"; caPrivateKey: string } | { mode: "key"; privateKey: string };

export type SshFailure = "unreachable" | "auth-failed" | "host-key-changed" | "host-key-unknown" | "timeout" | "error";

export class SshError extends Error {
  readonly kind: SshFailure;
  constructor(kind: SshFailure, message: string) {
    super(message);
    this.kind = kind;
  }
}

/** Certificates are valid from a minute ago (clock skew) to five minutes from now. */
const CERT_VALIDITY = "-1m:+5m";
const MAX_OUTPUT = 32 * 1024 * 1024;

function exec(
  cmd: string,
  args: string[],
  opts: { input?: string; timeoutMs?: number } = {},
): Promise<{ code: number | null; stdout: string; stderr: string; timedOut: boolean }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let size = 0;
    let timedOut = false;
    const timer = opts.timeoutMs ? setTimeout(() => ((timedOut = true), child.kill("SIGKILL")), opts.timeoutMs) : undefined;
    child.stdout.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_OUTPUT) child.kill("SIGKILL");
      else out.push(c);
    });
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8").slice(-4000), timedOut });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(opts.input ?? "");
  });
}

async function withDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  // tmpfs in the container (compose and the chart mount /tmp), so keys never reach the data volume.
  const dir = await mkdtemp(join(tmpdir(), "openasy-ssh-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const knownHost = (e: Endpoint) => (e.port === 22 ? e.address : `[${e.address}]:${e.port}`);

/** SHA256:... as OpenSSH prints it. */
export function fingerprint(keyLine: string): string {
  const blob = keyLine.trim().split(/\s+/)[1] ?? "";
  return `SHA256:${createHash("sha256").update(Buffer.from(blob, "base64")).digest("base64").replace(/=+$/, "")}`;
}

/** A new CA (or fixed key): OpenSSH private key and public key line. */
export async function generateKey(comment: string): Promise<{ privateKey: string; publicKey: string }> {
  return withDir(async (dir) => {
    const r = await exec("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", join(dir, "key")]);
    if (r.code !== 0) throw new Error(`ssh-keygen failed: ${r.stderr}`);
    return { privateKey: await readFile(join(dir, "key"), "utf8"), publicKey: (await readFile(join(dir, "key.pub"), "utf8")).trim() };
  });
}

export async function publicKeyOf(privateKey: string): Promise<string> {
  return withDir(async (dir) => {
    await writeFile(join(dir, "key"), privateKey, { mode: 0o600 });
    const r = await exec("ssh-keygen", ["-y", "-f", join(dir, "key")]);
    if (r.code !== 0) throw new Error(`ssh-keygen failed: ${r.stderr}`);
    return r.stdout.trim();
  });
}

/** Writes the identity for one connection: an ephemeral key with a 5-minute certificate, or the fixed key. */
async function identity(dir: string, cred: Credential, name: string, opts: { forwarding: boolean }): Promise<string[]> {
  const key = join(dir, name);
  if (cred.mode === "key") {
    await writeFile(key, cred.privateKey, { mode: 0o600 });
    return ["-i", key];
  }
  await writeFile(join(dir, "ca"), cred.caPrivateKey, { mode: 0o600 });
  let r = await exec("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "openasy-infra", "-f", key]);
  if (r.code !== 0) throw new Error(`ssh-keygen failed: ${r.stderr}`);
  // -O clear: no PTY, no forwarding, no agent, no X11. A jump host needs port forwarding to reach the target.
  const permits = ["-O", "clear", ...(opts.forwarding ? ["-O", "permit-port-forwarding"] : [])];
  r = await exec("ssh-keygen", [
    "-q",
    "-s",
    join(dir, "ca"),
    "-I",
    `openasy-infra-${Date.now()}`,
    "-n",
    ACCOUNT,
    "-V",
    CERT_VALIDITY,
    ...permits,
    `${key}.pub`,
  ]);
  if (r.code !== 0) throw new Error(`could not sign the certificate: ${r.stderr}`);
  return ["-i", key, "-o", `CertificateFile=${key}-cert.pub`];
}

function baseOptions(knownHosts: string, check: "yes" | "accept-new", timeoutSec: number) {
  return [
    "-F",
    "/dev/null",
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    `StrictHostKeyChecking=${check}`,
    "-o",
    `UserKnownHostsFile=${knownHosts}`,
    "-o",
    "GlobalKnownHostsFile=/dev/null",
    "-o",
    "UpdateHostKeys=no",
    "-o",
    `ConnectTimeout=${timeoutSec}`,
    "-o",
    "ServerAliveInterval=10",
    "-o",
    "ServerAliveCountMax=2",
    "-o",
    "RequestTTY=no",
    "-o",
    "ForwardAgent=no",
    "-o",
    "ForwardX11=no",
    "-o",
    "ClearAllForwardings=yes",
    "-o",
    "LogLevel=ERROR",
  ];
}

function classify(stderr: string, timedOut: boolean): SshError {
  const msg = stderr.trim().split("\n").filter(Boolean).pop() ?? "ssh failed";
  if (timedOut) return new SshError("timeout", "The collection took too long and was stopped.");
  if (/REMOTE HOST IDENTIFICATION HAS CHANGED|Host key for .* has changed/i.test(stderr))
    return new SshError("host-key-changed", "The host key changed. Check the host, then accept the new key.");
  if (/No .*host key is known|Host key verification failed/i.test(stderr)) return new SshError("host-key-unknown", "The host key is not pinned yet.");
  if (/Permission denied/i.test(stderr)) return new SshError("auth-failed", `Not allowed to log in: ${msg}`);
  if (/Connection refused|timed out|No route to host|Could not resolve|Network is unreachable|Connection closed by|kex_exchange_identification/i.test(stderr))
    return new SshError("unreachable", msg);
  return new SshError("error", msg);
}

async function sshArgs(dir: string, target: Endpoint, cred: Credential, jump: Endpoint | undefined, check: "yes" | "accept-new", timeoutSec: number) {
  const kh = join(dir, "known_hosts");
  const pinned = [target, ...(jump ? [jump] : [])].flatMap((e) => e.hostKeys.map((k) => `${knownHost(e)} ${k}`));
  await writeFile(kh, pinned.join("\n") + (pinned.length ? "\n" : ""), { mode: 0o600 });
  const args = [...baseOptions(kh, check, timeoutSec), ...(await identity(dir, cred, "id", { forwarding: false }))];
  if (jump) {
    // The jump host is checked against its own pinned key, always strictly, with its own certificate.
    const jumpId = await identity(dir, cred, "jump", { forwarding: true });
    const proxy = ["ssh", ...baseOptions(kh, "yes", timeoutSec), ...jumpId, "-W", "%h:%p", "-p", String(jump.port), `${jump.user}@${jump.address}`];
    args.push("-o", `ProxyCommand=${proxy.join(" ")}`);
  }
  args.push("-p", String(target.port), `${target.user}@${target.address}`);
  return { args, knownHosts: kh };
}

/** Runs the collection script with `sh -s` and returns its output. */
export async function runScript(target: Endpoint, cred: Credential, script: string, opts: { jump?: Endpoint; timeoutMs?: number } = {}): Promise<string> {
  if (!target.hostKeys.length) throw new SshError("host-key-unknown", "The host key is not pinned yet.");
  return withDir(async (dir) => {
    const { args } = await sshArgs(dir, target, cred, opts.jump, "yes", 15);
    const r = await exec("ssh", [...args, "sh", "-s"], { input: script, timeoutMs: opts.timeoutMs ?? 120_000 });
    if (r.code === 255 || r.timedOut) throw classify(r.stderr, r.timedOut);
    return r.stdout;
  });
}

/**
 * The host keys a host presents, for an admin to check before they are pinned. Connects once without trusting
 * anything; whether the login itself succeeds does not matter.
 */
export async function scanHostKey(target: Endpoint, cred: Credential, opts: { jump?: Endpoint } = {}): Promise<string[]> {
  return withDir(async (dir) => {
    const { args, knownHosts } = await sshArgs(dir, { ...target, hostKeys: [] }, cred, opts.jump, "accept-new", 10);
    const r = await exec("ssh", [...args, "true"], { timeoutMs: 30_000 });
    const lines = (await readFile(knownHosts, "utf8"))
      .split("\n")
      .filter((l) => l.startsWith(`${knownHost(target)} `))
      .map((l) => l.slice(knownHost(target).length + 1).trim());
    if (!lines.length) throw classify(r.stderr, r.timedOut);
    return [...new Set(lines)];
  });
}
