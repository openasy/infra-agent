// The loop: ask Infrastructure for work, run it, send the results. Infrastructure being down never stops the agent;
// it says so in /readyz and keeps asking (ADR 0023).
import { enroll, InfraError, sendResult, work, type Report } from "./client.ts";
import { runJob, type Transport } from "./jobs.ts";
import type { Keyring } from "./kek.ts";
import { log } from "./log.ts";
import { authorizedKeyLine, hostSetup, sshdConfig, sudoers } from "./setup.ts";
import { publicKeyOf } from "./ssh.ts";
import { saveState, type AgentState } from "./state.ts";

export interface AgentOptions {
  url: string;
  version: string;
  state: AgentState;
  statePath: string;
  keyring: Keyring;
  enrollToken?: string;
  concurrency?: number;
  transport?: Transport;
}

export interface Status {
  enrolled: boolean;
  infraOk: boolean;
  lastError: string | null;
  lastContactAt: string | null;
  jobs: number;
  jobFailures: number;
  running: number;
}

export async function createAgent(o: AgentOptions) {
  const caPublicKey = await publicKeyOf(o.state.caPrivateKey);
  const keyPublicKey = await publicKeyOf(o.state.keyPrivateKey);
  const status: Status = { enrolled: !!o.state.secret, infraOk: false, lastError: null, lastContactAt: null, jobs: 0, jobFailures: 0, running: 0 };
  const limit = o.concurrency ?? 8;
  const report = (): Report => ({
    version: o.version,
    caPublicKey,
    keyPublicKey,
    setup: { sshdConfig: sshdConfig(), sudoers: sudoers(), hostSetup: hostSetup(caPublicKey, { sudo: true, containers: false }), authorizedKey: authorizedKeyLine(keyPublicKey) },
    running: status.running,
  });
  const failed = (err: unknown) => {
    status.infraOk = false;
    status.lastError = (err as Error).message;
    log("warn", "Infrastructure call failed", { status: (err as InfraError).status, error: status.lastError });
  };

  /** Enrolls once with the one-time token; afterwards the agent has its own secret (ADR 0023). */
  async function ensureEnrolled(): Promise<boolean> {
    if (o.state.secret) return true;
    if (!o.enrollToken) {
      status.lastError = "Not enrolled: add this agent in Infrastructure under Settings, Agents, and start it with INFRA_ENROLL_TOKEN";
      return false;
    }
    try {
      const r = await enroll(o.url, o.enrollToken, report());
      o.state.agentId = r.agentId;
      o.state.secret = r.secret;
      saveState(o.statePath, o.keyring, o.state);
      status.enrolled = true;
      log("info", "enrolled", { agentId: r.agentId });
      return true;
    } catch (err) {
      failed(err);
      return false;
    }
  }

  /** One round: ask for work, run up to `concurrency` jobs at a time, send each result as it finishes. */
  async function round() {
    if (!(await ensureEnrolled())) return;
    let jobs: unknown[];
    try {
      jobs = (await work(o.url, o.state.secret!, report())).jobs;
      status.infraOk = true;
      status.lastError = null;
      status.lastContactAt = new Date().toISOString();
    } catch (err) {
      failed(err);
      return;
    }
    const queue = [...jobs];
    await Promise.all(
      Array.from({ length: Math.min(limit, queue.length) }, async () => {
        for (let j = queue.shift(); j; j = queue.shift()) {
          status.running++;
          try {
            const result = await runJob(j, o.state, o.transport);
            status.jobs++;
            if (!result.ok) status.jobFailures++;
            await sendResult(o.url, o.state.secret!, result).catch(failed);
          } finally {
            status.running--;
          }
        }
      }),
    );
  }

  return { round, status, caPublicKey };
}
