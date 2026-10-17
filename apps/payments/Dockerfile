# syntax=docker/dockerfile:1.7
FROM node:20-slim AS base
RUN corepack enable \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /repo

FROM base AS deps
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json ./
COPY libs/bastion-common/package.json libs/bastion-common/
COPY apps/payments/package.json apps/payments/
RUN pnpm install --frozen-lockfile

FROM deps AS build
COPY tsconfig.base.json tsconfig.json ./
COPY libs libs
COPY apps/payments apps/payments
RUN pnpm --filter @bastion/common build \
 && pnpm exec tsc -p apps/payments/tsconfig.app.json

FROM node:20-slim AS runtime
WORKDIR /app
COPY --from=build --chown=node:node /repo/dist/apps/payments ./dist
COPY --from=build --chown=node:node /repo/libs/bastion-common/dist ./node_modules/@bastion/common/dist
COPY --from=build --chown=node:node /repo/libs/bastion-common/package.json ./node_modules/@bastion/common/package.json
COPY --from=build --chown=node:node /repo/node_modules ./node_modules
ENV NODE_ENV=production
USER node
EXPOSE 8445 9093
CMD ["node", "dist/apps/payments/src/main.js"]
