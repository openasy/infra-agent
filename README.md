# infra-agent

[![CI](https://github.com/openasy/infra-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/infra-agent/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The agent of [OpenAsy Infrastructure](https://github.com/openasy/infra). It is installed **once**, next to
Infrastructure or in the network of the hosts, and reads those hosts over SSH at intervals. **Nothing is installed
on the hosts** (ADR 0018, 0031).

- **It keeps the keys.** On first start it makes its SSH certificate authority and a fixed key, and keeps them in
  `/data/agent.state`, sealed with its own key-encryption key. Infrastructure never sees a private key.
- **It runs only its own script.** Infrastructure says which host to read; the agent checks every job again (address,
  account, port, host keys), runs the read-only script built into it (`agent/collect.sh`), and signs certificates for
  the `openasy` principal only, valid for 5 minutes. A compromised Infrastructure cannot run commands on any host.
- **It masks secrets before they leave.** Container environment variables are kept by name only; passwords, tokens
  and keys in command lines become `***`.
- **It connects out, never in.** It asks Infrastructure for work and sends results; Infrastructure never connects to
  it. It enrols once with a one-time token and then uses its own secret (ADR 0023). When Infrastructure is down it
  keeps asking and says so in `/readyz`.

## Run

Add the agent in Infrastructure under Settings, Agents. It shows a one-time enrolment token and this command:

```bash
openssl rand -hex 32 > openasy-agent-kek   # keep it with your backups
docker run -d --name infra-agent --restart unless-stopped --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  -v infra-agent-data:/data -v "$PWD/openasy-agent-kek:/run/secrets/openasy-agent-kek:ro" \
  -e INFRA_URL=https://infra.example.com -e INFRA_ENROLL_TOKEN=oie_... \
  ghcr.io/openasy/infra-agent:0.1.0
```

Next to Infrastructure, its compose file has the agent already. The agent must be the same version as Infrastructure
(ADR 0019); another version is refused.

| Variable | Default | |
| --- | --- | --- |
| `INFRA_URL` | | Where Infrastructure is, such as `http://infra:8080` or its https:// address |
| `INFRA_ENROLL_TOKEN` | | One-time, for the first start only |
| `INFRA_AGENT_SECRETS_KEY_FILE` | `/run/secrets/openasy-agent-kek` | 32-byte key that seals the CA, keys and secret |
| `INFRA_AGENT_STATE` | `/data/agent.state` | The sealed state, on its volume |
| `POLL_SECONDS` | `10` | How often it asks for work |
| `CONCURRENCY` | `8` | Hosts read at the same time |
| `PORT` | `9100` | `/healthz`, `/readyz` and `/metrics` |

## What it reads, and what a host needs

See [Infrastructure](https://github.com/openasy/infra#prepare-a-host). Setup in Infrastructure prints the commands
for a host with this agent's CA, and the sudoers file that matches `agent/collect.sh` exactly.

## Develop

```bash
npm install
npm test   # parsing and masking against outputs captured on Debian, Alpine and Rocky Linux, jobs, the loop
```

The end-to-end test lives in [infra](https://github.com/openasy/infra/tree/main/e2e) and runs both images against real
sshd hosts, a jump host, Docker and a kind cluster.

## Licence

AGPL-3.0 (ADR 0008).
