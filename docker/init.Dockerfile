# syntax=docker/dockerfile:1.7
FROM node:20-slim
RUN corepack enable \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq unzip \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://releases.hashicorp.com/vault/1.17.2/vault_1.17.2_linux_amd64.zip -o /tmp/vault.zip \
 && unzip /tmp/vault.zip -d /usr/local/bin \
 && rm /tmp/vault.zip \
 && chmod +x /usr/local/bin/vault
WORKDIR /repo
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json tsconfig.json ./
COPY libs libs
COPY scripts scripts
RUN pnpm install --frozen-lockfile
CMD ["sleep", "infinity"]
