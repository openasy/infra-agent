// What the agent keeps on its own volume (ADR 0021, 0031): its SSH certificate authority, its fixed key and the
// secret it got when it enrolled, sealed with its own key-encryption key. Infrastructure never sees the private keys.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Keyring } from "./kek.ts";
import { generateKey } from "./ssh.ts";

export interface AgentState {
  caPrivateKey: string;
  keyPrivateKey: string;
  /** Set once enrolled: who this agent is to Infrastructure. */
  agentId?: string;
  secret?: string;
}

export async function loadState(path: string, keyring: Keyring): Promise<AgentState> {
  let sealed: string | undefined;
  try {
    sealed = readFileSync(path, "utf8").trim();
  } catch {
    sealed = undefined;
  }
  if (sealed) return JSON.parse(keyring.open(sealed).toString("utf8")) as AgentState;
  // First start: the CA and the fixed key are made here and never leave the agent.
  const state: AgentState = {
    caPrivateKey: (await generateKey("OpenAsy infra-agent CA")).privateKey,
    keyPrivateKey: (await generateKey("openasy-infra")).privateKey,
  };
  saveState(path, keyring, state);
  return state;
}

export function saveState(path: string, keyring: Keyring, state: AgentState) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, keyring.seal(JSON.stringify(state)), { mode: 0o600 });
  renameSync(tmp, path);
}
