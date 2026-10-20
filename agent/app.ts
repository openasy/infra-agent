import type { IncomingMessage, ServerResponse } from "node:http";
import type { Status } from "./agent.ts";

function send(res: ServerResponse, status: number, body: string, type = "application/json") {
  res.writeHead(status, { "content-type": type, "content-length": Buffer.byteLength(body), "x-content-type-options": "nosniff" });
  res.end(body);
}

/** Health and metrics for the agent (ADR 0017). The agent has no API of its own. */
export function createAgentHandler(version: string, s: Status) {
  return (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    if (path === "/healthz") return send(res, 200, JSON.stringify({ status: "ok" }));
    if (path === "/readyz") {
      const problems = [!s.enrolled && "not enrolled", !s.infraOk && `Infrastructure unreachable${s.lastError ? `: ${s.lastError}` : ""}`].filter(Boolean);
      return send(res, problems.length ? 503 : 200, JSON.stringify(problems.length ? { status: "degraded", problems } : { status: "ready" }));
    }
    if (path === "/metrics") {
      const lines = [
        "# HELP openasy_build_info Build information.",
        "# TYPE openasy_build_info gauge",
        `openasy_build_info{product="infra-agent",version="${version}"} 1`,
        "# HELP openasy_infra_agent_jobs_total Collections and host key requests run.",
        "# TYPE openasy_infra_agent_jobs_total counter",
        `openasy_infra_agent_jobs_total ${s.jobs}`,
        "# HELP openasy_infra_agent_job_failures_total Jobs that failed (host unreachable, login refused, host key changed).",
        "# TYPE openasy_infra_agent_job_failures_total counter",
        `openasy_infra_agent_job_failures_total ${s.jobFailures}`,
        "# HELP openasy_infra_agent_running Jobs running now.",
        "# TYPE openasy_infra_agent_running gauge",
        `openasy_infra_agent_running ${s.running}`,
        "# HELP openasy_infra_agent_last_contact_timestamp_seconds Last successful call to Infrastructure; 0 before the first.",
        "# TYPE openasy_infra_agent_last_contact_timestamp_seconds gauge",
        `openasy_infra_agent_last_contact_timestamp_seconds ${s.lastContactAt ? Math.floor(Date.parse(s.lastContactAt) / 1000) : 0}`,
      ];
      return send(res, 200, lines.join("\n") + "\n", "text/plain; version=0.0.4");
    }
    send(res, 404, JSON.stringify({ status: "not found" }));
  };
}
