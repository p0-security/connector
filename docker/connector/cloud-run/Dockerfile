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

FROM us-west1-docker.pkg.dev/p0-prod/chainguard/p0.dev/p0-node:24.22.1
ARG WORKSPACE
ARG BUILD_DATE
ARG GIT_REF
ENV WORKSPACE=${WORKSPACE}
ENV BUILD_DATE=$BUILD_DATE
ENV GIT_REF=$GIT_REF
# This image is built only for P0's own service connectors (see
# .github/workflows/docker.yaml), which are deployed as private Cloud Run
# services: P0's service account holds roles/run.invoker, and Cloud Run IAM
# turns away a token minted for another service. So they skip the
# connector's own `aud` comparison unless the deployment sets
# CONNECTOR_AUDIENCE, which takes precedence. Off Cloud Run (no K_SERVICE) the
# opt-out makes the connector refuse to start without CONNECTOR_AUDIENCE.
# Don't copy this into the SDK's example image: a Custom Application connector
# sets the opt-out in its own deploy config, where it's visible.
ENV CONNECTOR_AUDIENCE_CHECK=cloud-run-iam

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
