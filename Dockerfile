# syntax=docker/dockerfile:1

# OpenSSH's own client does the SSH (ADR 0031): Debian slim with openssh-client rather than distroless. The agent has
# no runtime dependencies: Node runs the TypeScript sources directly.
FROM node:26.12.0-trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
  && rm -rf /var/lib/apt/lists/* /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /opt/yarn* /usr/local/bin/yarn* \
  && mkdir -p /data && chown node:node /data
WORKDIR /app
COPY package.json ./
COPY agent ./agent
# The CA, the fixed key and the agent's secret live sealed in /data; SSH keys for one connection in /tmp (tmpfs).
ENV NODE_ENV=production PORT=9100 INFRA_AGENT_STATE=/data/agent.state
VOLUME /data
EXPOSE 9100
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:9100/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "agent/main.ts"]
