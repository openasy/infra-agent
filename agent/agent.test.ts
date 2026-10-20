import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { createAgent } from "./agent.ts";
import { checkJob, runJob, type Transport } from "./jobs.ts";
import { createKeyring } from "./kek.ts";
import { SshError } from "./ssh.ts";
import { loadState } from "./state.ts";

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");
const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFmXq7hWQvK1eF4s3n0q6X8b9mZ2nqJ8V7cJq3s1kR2x";
const job = (over: Record<string, unknown> = {}) => ({
  id: "j1",
  hostId: "h1",
  action: "collect",
  target: { address: "10.0.0.5", port: 22, user: "openasy", auth: "certificate", containers: false, hostKeys: [KEY] },
  jump: null,
  ...over,
});
const keys = { caPrivateKey: "ca", keyPrivateKey: "key" };

describe("jobs from Infrastructure", () => {
  it.each([
    ["an address ssh would read as an option", { target: { ...job().target, address: "-oProxyCommand=sh -c id" } }],
    ["a user ssh would read as an option", { target: { ...job().target, user: "-oX" } }],
    ["a host key that is not a public key", { target: { ...job().target, hostKeys: ["ssh-ed25519 AAAA\nmalicious"] } }],
    ["an action the agent does not know", { action: "run", command: "rm -rf /" }],
    ["a jump host without a pinned key", { jump: { address: "j", port: 22, user: "openasy", hostKeys: [] } }],
    ["a port out of range", { target: { ...job().target, port: 70000 } }],
  ])("refuses %s", async (_name, over) => {
    expect(() => checkJob(job(over))).toThrow();
    const r = await runJob(job(over), keys, { runScript: () => Promise.reject(new Error("must not connect")), scanHostKey: () => Promise.reject(new Error("must not connect")) });
    expect(r).toMatchObject({ ok: false, error: { kind: "invalid-job" } });
  });

  it("runs only its own script, and parses and masks the output before sending it", async () => {
    let script = "";
    const transport: Transport = {
      runScript: async (_e, cred, s) => {
        expect(cred).toEqual({ mode: "certificate", caPrivateKey: "ca" });
        script = s;
        return fixture("debian-unprivileged-containers.txt");
      },
      scanHostKey: async () => [KEY],
    };
    const r = await runJob(job({ target: { ...job().target, containers: true }, script: "rm -rf /" }), keys, transport);
    expect(script.startsWith("OPENASY_CONTAINERS=1\n# Read-only collection")).toBe(true);
    expect(r.ok && "facts" in r && r.facts.containers?.map((c) => c.name)).toContain("fx-api");
    expect(JSON.stringify(r)).not.toMatch(/hunter2-fixture|fixture-token-123/);
  });

  it("reports the key a host presents when it changed", async () => {
    const other = KEY.replace("Fm", "Gm");
    const r = await runJob(job(), keys, { runScript: async () => Promise.reject(new SshError("host-key-changed", "changed")), scanHostKey: async () => [other] });
    expect(r).toEqual({ jobId: "j1", hostId: "h1", ok: false, error: { kind: "host-key-changed", message: "changed" }, hostKeys: [other] });
  });
});

describe("the loop", () => {
  const servers: Array<{ close: () => void }> = [];
  afterEach(() => servers.splice(0).forEach((s) => s.close()));

  async function fakeInfra(opts: { jobs: unknown[]; version?: string }) {
    const seen: Array<{ path: string; auth: string | undefined; body: Record<string, any> }> = [];
    const server = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = JSON.parse(gunzipSync(Buffer.concat(chunks)).toString());
      seen.push({ path: req.url!, auth: req.headers.authorization, body });
      const json = (status: number, data: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(data));
      if (req.url === "/api/v1/agent/enroll") return body.token === "enroll-1" ? json(200, { agentId: "a1", secret: "agent-secret" }) : json(401, { code: "invalid-token", detail: "used" });
      if (req.headers.authorization !== "Bearer agent-secret") return json(401, { code: "invalid-token" });
      if (req.url === "/api/v1/agent/work") return body.version === (opts.version ?? "1.0.0") ? json(200, { jobs: opts.jobs.splice(0) }) : json(409, { code: "version-mismatch", detail: "infra-agent 1.0.0 does not match infra 2.0.0" });
      if (req.url === "/api/v1/agent/results") return json(202, { status: "accepted" });
      json(404, {});
    });
    await new Promise<void>((r) => server.listen(0, r));
    servers.push(server);
    return { url: `http://localhost:${(server.address() as AddressInfo).port}`, seen };
  }

  async function agent(url: string, enrollToken?: string) {
    const dir = mkdtempSync(join(tmpdir(), "agent-"));
    const keyring = createKeyring(randomBytes(32));
    const statePath = join(dir, "agent.state");
    const state = await loadState(statePath, keyring);
    return {
      statePath,
      keyring,
      a: await createAgent({ url, version: "1.0.0", state, statePath, keyring, enrollToken, transport: { runScript: async () => fixture("debian-sudo.txt"), scanHostKey: async () => [KEY] } }),
    };
  }

  it("enrolls once, asks for work and sends results with its own secret", async () => {
    const infra = await fakeInfra({ jobs: [job(), job({ id: "j2", action: "host-key" })] });
    const { a, statePath, keyring } = await agent(infra.url, "enroll-1");
    await a.round();
    expect(a.status).toMatchObject({ enrolled: true, infraOk: true, jobs: 2, jobFailures: 0 });
    const enroll = infra.seen.find((s) => s.path === "/api/v1/agent/enroll")!;
    expect(enroll.body).toMatchObject({ token: "enroll-1", version: "1.0.0", caPublicKey: expect.stringMatching(/^ssh-ed25519 /) });
    expect(enroll.body.setup.sudoers).toContain("Cmnd_Alias OPENASY_READ");
    // No private key ever leaves the agent.
    expect(JSON.stringify(infra.seen)).not.toMatch(/PRIVATE KEY/);
    const results = infra.seen.filter((s) => s.path === "/api/v1/agent/results");
    expect(results.map((r) => r.auth)).toEqual(["Bearer agent-secret", "Bearer agent-secret"]);
    expect(results.find((r) => r.body.jobId === "j1")!.body.facts.system.hostname).toBe("web-1");
    expect(results.find((r) => r.body.jobId === "j2")!.body.hostKeys).toEqual([KEY]);
    // The secret is kept sealed: the file never holds it in clear.
    expect(readFileSync(statePath, "utf8")).not.toContain("agent-secret");
    expect(JSON.parse(keyring.open(readFileSync(statePath, "utf8")).toString()).secret).toBe("agent-secret");
  });

  it("waits without an enrolment token and says why", async () => {
    const infra = await fakeInfra({ jobs: [] });
    const { a } = await agent(infra.url);
    await a.round();
    expect(a.status).toMatchObject({ enrolled: false, lastError: expect.stringContaining("INFRA_ENROLL_TOKEN") });
    expect(infra.seen).toEqual([]);
  });

  it("keeps running when Infrastructure is down or refuses its version", async () => {
    const { a } = await agent("http://127.0.0.1:1", "enroll-1");
    await a.round();
    expect(a.status).toMatchObject({ enrolled: false, infraOk: false, lastError: expect.stringContaining("unreachable") });
    const infra = await fakeInfra({ jobs: [job()], version: "2.0.0" });
    const b = await agent(infra.url, "enroll-1");
    await b.a.round();
    expect(b.a.status).toMatchObject({ enrolled: true, infraOk: false, lastError: expect.stringContaining("does not match"), jobs: 0 });
  });
});
