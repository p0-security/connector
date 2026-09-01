# syntax=docker/dockerfile:1

# A Cloud Run image for a P0 Custom Application connector.
#
# Cloud Run runs linux/amd64. If you build locally on an arm64 machine (Apple
# silicon), pass --platform linux/amd64 or the revision will fail to start with
# an exec format error. `gcloud builds submit` already builds amd64.

# ---------------------------------------------------------------- build stage
FROM node:24-slim AS build

WORKDIR /app

# Copy manifests first so the dependency layer is cached across source edits.
# `npm ci` is used when a lockfile is committed (recommended for anything you
# actually deploy); `npm install` covers the checked-in example, which has none.
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# -------------------------------------------------------------- runtime stage
FROM node:24-slim AS runtime

ENV NODE_ENV=production

WORKDIR /app

COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi \
  && npm cache clean --force

COPY --from=build /app/dist ./dist

# `dist/index.js` reads ../package.json for the version it reports to P0 via
# `app.metadata.get`, so the manifest copied above has to stay alongside dist.

# Cloud Run injects $PORT and ignores EXPOSE; both are here so that a plain
# `docker run -p 8080:8080` behaves the same way locally.
ENV PORT=8080
EXPOSE 8080

USER node

CMD ["node", "dist/index.js"]
