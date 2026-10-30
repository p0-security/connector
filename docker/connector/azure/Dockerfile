# When changing node version, please update the .nvmrc to match
FROM us-west1-docker.pkg.dev/p0-prod/chainguard/p0.dev/p0-node:24.22.1-dev AS build
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

# A Connector opts in to Azure by adding `src/run-azure.ts`, which builds to
# `dist/run-azure.js`, and a `<name>-azure` row using this Dockerfile in
# .github/workflows/docker.yaml. Fail the build, not the container, if
# `dist/run-azure.js` is missing.
RUN --mount=type=cache,target=$YARN_CACHE_FOLDER \
  yarn workspaces focus --all && \
  yarn workspaces foreach --recursive --topological --from "${WORKSPACE}" run build && \
  yarn workspace "${WORKSPACE}" exec test -f dist/run-azure.js && \
  yarn workspaces focus --production "${WORKSPACE}"

# Stage an entrypoint that lets yarn locate the workspace (no DIR knowledge needed)
# and run its Azure entry point.
RUN printf '%s\n%s\n' \
  '#!/bin/sh' \
  'exec yarn workspace "$WORKSPACE" exec node dist/run-azure.js' \
  > /app/entrypoint.sh && \
  chmod +x /app/entrypoint.sh

FROM us-west1-docker.pkg.dev/p0-prod/chainguard/p0.dev/p0-node:24.22.1
ARG WORKSPACE
ARG BUILD_DATE
ARG GIT_REF
ENV WORKSPACE=${WORKSPACE}
ENV BUILD_DATE=$BUILD_DATE
ENV GIT_REF=$GIT_REF

USER root
RUN npm install -g corepack && corepack enable yarn
# npm exists only to install corepack. The runtime calls yarn. node-gyp is a
# build tool the runtime never loads. npm bundles unpatched
# http-cache-semantics, and node-gyp bundles undici 8.11.2.
RUN rm -rf /usr/lib/node_modules/npm /usr/lib/node_modules/node-gyp \
 && rm -f /usr/bin/npm /usr/bin/npx \
 && rm -f /var/lib/db/sbom/npm-*.spdx.json /var/lib/db/sbom/node-gyp-*.spdx.json

USER node
COPY --from=build --chown=node:node /app /app
WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]
