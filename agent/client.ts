// Everything the agent sends goes to the Infrastructure API, and only that way (ADR 0018, 0023): the agent
// accepts no requests from Infrastructure. It asks for work and sends results.
import { gzipSync } from "node:zlib";
import type { Result } from "./jobs.ts";

export interface Report {
  version: string;
  caPublicKey: string;
  keyPublicKey: string;
  /** What admins put on hosts for this agent: its CA and the sudoers file matching its script. */
  setup: { sshdConfig: string; sudoers: string; hostSetup: string; authorizedKey: string };
  /** Jobs running now. */
  running: number;
}

export class InfraError extends Error {
  readonly status: number | undefined;
  readonly code: string | undefined;
  constructor(status: number | undefined, code: string | undefined, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function call<T>(url: string, path: string, init: { secret?: string; body: unknown; timeoutMs?: number }): Promise<T> {
  let res: Response;
  try {
    res = await fetch(new URL(path, url), {
      method: "POST",
      headers: { ...(init.secret && { authorization: `Bearer ${init.secret}` }), "content-type": "application/json", "content-encoding": "gzip" },
      body: gzipSync(JSON.stringify(init.body)),
      signal: AbortSignal.timeout(init.timeoutMs ?? 15_000),
    });
  } catch (err) {
    throw new InfraError(undefined, "unreachable", `Infrastructure at ${url} is unreachable: ${(err as Error).message}`);
  }
  if (!res.ok) {
    const p = (await res.json().catch(() => ({}))) as { code?: string; detail?: string; title?: string };
    throw new InfraError(res.status, p.code, p.detail ?? p.title ?? `${res.status}`);
  }
  return (await res.json()) as T;
}

export const enroll = (url: string, token: string, report: Report) =>
  call<{ agentId: string; secret: string }>(url, "/api/v1/agent/enroll", { body: { token, ...report } });
export const work = (url: string, secret: string, report: Report) => call<{ jobs: unknown[] }>(url, "/api/v1/agent/work", { secret, body: report });
export const sendResult = (url: string, secret: string, result: Result) =>
  call<{ status: string }>(url, "/api/v1/agent/results", { secret, body: result, timeoutMs: 60_000 });
