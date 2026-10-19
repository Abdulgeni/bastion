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
COPY apps/orders/package.json apps/orders/
RUN pnpm install --frozen-lockfile

FROM deps AS build
COPY tsconfig.base.json tsconfig.json ./
COPY libs libs
COPY apps/orders apps/orders
RUN pnpm --filter @bastion/common build \
 && pnpm exec tsc -p apps/orders/tsconfig.app.json

FROM deps AS deploy
COPY --from=build /repo/dist ./dist
COPY --from=build /repo/libs/bastion-common/dist ./libs/bastion-common/dist
RUN pnpm --filter=@bastion/orders deploy --prod /deploy \
 && rm -rf /deploy/dist \
 && cp -r /repo/dist /deploy/dist \
 && cp -r libs/bastion-common/dist /deploy/node_modules/@bastion/common/dist

FROM node:20-slim AS runtime
WORKDIR /app
COPY --from=deploy --chown=node:node /deploy/ ./
ENV NODE_ENV=production
USER node
EXPOSE 8443 9091
CMD ["node", "dist/apps/orders/apps/orders/src/main.js"]
