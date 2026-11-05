# syntax=docker/dockerfile:1
#
# syncert relay. Build from the repository root:
#   docker build -f apps/server/Dockerfile -t syncert-server .
#   docker run -d -p 8787:8787 -v syncert-data:/data syncert-server

ARG NODE_VERSION=24

# ---- build ------------------------------------------------------------------
FROM node:${NODE_VERSION}-alpine AS build
WORKDIR /src
RUN corepack enable

# Install dependencies first so this layer is cached across source changes.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/protocol/package.json packages/protocol/
COPY packages/crypto/package.json packages/crypto/
COPY packages/core/package.json packages/core/
COPY apps/server/package.json apps/server/
RUN pnpm install --frozen-lockfile

COPY tsconfig.base.json ./
COPY packages packages
COPY apps/server apps/server
# Build the server and its workspace deps, then assemble a self-contained
# production tree in /out. better-sqlite3 bundles prebuilt N-API addons for
# every platform (no compiler needed); keep only the musl ones for Alpine.
RUN pnpm --filter @syncert/server... build \
 && pnpm --filter @syncert/server deploy --prod --legacy /out \
 && find /out/node_modules/.pnpm -path '*better-sqlite3/prebuilds/*.node' ! -name 'linuxmusl-*' -delete

# ---- runtime ----------------------------------------------------------------
FROM node:${NODE_VERSION}-alpine
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8787 \
    DATA_DIR=/data
WORKDIR /app
COPY --from=build /out ./
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+process.env.PORT+'/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "dist/cli.js"]
