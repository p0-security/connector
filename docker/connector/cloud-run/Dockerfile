# When changing node version, please update the .nvmrc to match
FROM us-west1-docker.pkg.dev/p0-prod/chainguard/p0.dev/p0-node:24.22.0-dev AS build
ARG WORKSPACE
ARG BUILD_DATE
ARG GIT_REF
RUN test -n "$WORKSPACE" || (echo "WORKSPACE build arg is required" && exit 1)
RUN test -n "$BUILD_DATE" || (echo "BUILD_DATE build arg is required" && exit 1)
RUN test -n "$GIT_REF" || (echo "GIT_REF build arg is required" && exit 1)
USER root
RUN corepack enable yarn

WORKDIR /app
COPY .yarn.lock yarn.lock
COPY ./ ./

ENV YARN_CACHE_FOLDER=/root/.yarn

RUN --mount=type=cache,target=$YARN_CACHE_FOLDER \
  yarn workspaces focus --all && \
  yarn workspaces foreach --recursive --topological --from "${WORKSPACE}" run build && \
  yarn workspaces focus --production "${WORKSPACE}"

# Stage an entrypoint that lets yarn locate the workspace (no DIR knowledge needed)
# and run its bin (whose name is the unscoped workspace name).
RUN printf '%s\n%s\n' \
  '#!/bin/sh' \
  'exec yarn workspace "$WORKSPACE" run "${WORKSPACE##*/}"' \
  > /app/entrypoint.sh && \
  chmod +x /app/entrypoint.sh

FROM us-west1-docker.pkg.dev/p0-prod/chainguard/p0.dev/p0-node:24.22.0
ARG WORKSPACE
ARG BUILD_DATE
ARG GIT_REF
ENV WORKSPACE=${WORKSPACE}
ENV BUILD_DATE=$BUILD_DATE
ENV GIT_REF=$GIT_REF

USER root
RUN npm install -g corepack && corepack enable yarn
# npm exists only to install corepack. The runtime calls yarn, and the npm
# tree Chainguard ships bundles unpatched http-cache-semantics.
RUN rm -rf /usr/lib/node_modules/npm \
 && rm -f /usr/bin/npm /usr/bin/npx \
 && rm -f /var/lib/db/sbom/npm-*.spdx.json

USER node
COPY --from=build --chown=node:node /app /app
WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]
