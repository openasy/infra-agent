import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAgent } from "./agent.ts";
import { createAgentHandler } from "./app.ts";
import { createKeyring } from "./kek.ts";
import { log } from "./log.ts";
import { loadState } from "./state.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const url = process.env.INFRA_URL;
if (!url) {
  log("error", "INFRA_URL is required: the address of Infrastructure, such as http://infra:8080");
  process.exit(1);
}
const keyFile = process.env.INFRA_AGENT_SECRETS_KEY_FILE ?? "/run/secrets/openasy-agent-kek";
let kek: Buffer;
try {
  const text = readFileSync(keyFile, "utf8").trim();
  kek = /^[0-9a-f]{64}$/i.test(text) ? Buffer.from(text, "hex") : Buffer.from(text, "base64");
  if (kek.length !== 32) throw new Error("not 32 bytes");
} catch (err) {
  // The agent holds the SSH CA every host trusts: it does not start without the key that encrypts it (ADR 0021).
  log("error", "no key-encryption key: mount 32 random bytes (openssl rand -hex 32)", { file: keyFile, error: String(err) });
  process.exit(1);
}
const keyring = createKeyring(kek);
const statePath = process.env.INFRA_AGENT_STATE ?? "/data/agent.state";
const state = await loadState(statePath, keyring);
const pollSeconds = Number(process.env.POLL_SECONDS ?? 10);
const agent = await createAgent({ url, version, state, statePath, keyring, enrollToken: process.env.INFRA_ENROLL_TOKEN || undefined, concurrency: Number(process.env.CONCURRENCY ?? 8) });

const port = Number(process.env.PORT ?? 9100);
const server = createServer(createAgentHandler(version, agent.status));
server.listen(port, () => log("info", "infra-agent started", { version, port, infra: url, enrolled: agent.status.enrolled }));
log("info", "SSH certificate authority", { publicKey: agent.caPublicKey });

let busy = false;
const tick = () => {
  if (busy) return;
  busy = true;
  agent
    .round()
    .catch((err: unknown) => log("error", "round failed", { error: String(err) }))
    .finally(() => (busy = false));
};
tick();
const timer = setInterval(tick, pollSeconds * 1000);

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  clearInterval(timer);
  setTimeout(() => process.exit(1), 10_000).unref();
  server.close(() => process.exit(0));
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
