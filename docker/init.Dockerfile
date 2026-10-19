# syntax=docker/dockerfile:1.7
FROM node:20-slim
RUN corepack enable \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq unzip gosu \
 && rm -rf /var/lib/apt/lists/*
RUN corepack prepare pnpm@9.12.0 --activate
RUN mkdir -p /home/node/.cache/node \
 && cp -r /root/.cache/node/corepack /home/node/.cache/node/ \
 && chown -R node:node /home/node/.cache
RUN curl -fsSL https://releases.hashicorp.com/vault/1.17.2/vault_1.17.2_linux_amd64.zip -o /tmp/vault.zip \
 && unzip /tmp/vault.zip -d /usr/local/bin \
 && rm /tmp/vault.zip \
 && chmod +x /usr/local/bin/vault
WORKDIR /repo
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json tsconfig.json ./
COPY libs libs
COPY scripts scripts
RUN pnpm install --frozen-lockfile && chown -R node:node /repo
# Runs as root so it can chown the mounted /var/bastion and /var/bastion/jwt
# (which the named volume creates as root:root), then drops to node before
# running the user's command. That's how UID 1000 ends up owning the files.
COPY --chmod=0755 <<'WRAP' /usr/local/bin/drop-privs.sh
#!/bin/sh
set -eu
if [ "$(id -u)" = "0" ]; then
  mkdir -p /var/bastion/jwt 2>/dev/null || true
  chown -R node:node /var/bastion 2>/dev/null || true
  exec gosu node "$@"
fi
exec "$@"
WRAP
ENTRYPOINT ["/usr/local/bin/drop-privs.sh"]
ENV COREPACK_HOME=/home/node/.cache/node/corepack
CMD ["sleep", "infinity"]
