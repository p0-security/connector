# The 1Password connector's Lambda image: the shared Lambda image
# (docker/connector/lambda/Dockerfile), plus the 1Password SDK. The SDK
# reads its WebAssembly core from disk, so it can't be bundled into
# index.mjs and ships in node_modules beside it. Copied rather than shared,
# so that adding 1Password changes no other connector's image.
# Define custom function directory
ARG FUNCTION_DIR="/var/task"
# If you change the major version of node here, ensure the Lambda base image is also updated below.
FROM us-west1-docker.pkg.dev/p0-prod/chainguard/p0.dev/p0-node:24.22.1-dev AS build
ARG WORKSPACE
ARG BUILD_DATE
ARG GIT_REF
ARG FUNCTION_DIR
RUN test -n "$WORKSPACE" || (echo "WORKSPACE build arg is required" && exit 1)
RUN test -n "$BUILD_DATE" || (echo "BUILD_DATE build arg is required" && exit 1)
RUN test -n "$GIT_REF" || (echo "GIT_REF build arg is required" && exit 1)
ENV WORKSPACE=$WORKSPACE
ENV BUILD_DATE=$BUILD_DATE
ENV GIT_REF=$GIT_REF

USER root

RUN corepack enable yarn

WORKDIR /app
COPY .yarn.lock yarn.lock
COPY ./ ./
ENV YARN_CACHE_FOLDER=/root/.yarn
RUN --mount=type=cache,target=$YARN_CACHE_FOLDER \
  yarn workspaces focus --all && \
  yarn workspaces foreach --recursive --topological --from "${WORKSPACE}" run build && \
  yarn workspace "${WORKSPACE}" run build-within-docker && \
  yarn workspace "${WORKSPACE}" exec sh -c 'ln -s "$(pwd)/dist" /app/dist'
# The final stage copies these paths, so fail here if the SDK moved.
RUN test -f /app/node_modules/@1password/sdk/dist/sdk.js && \
  test -f /app/node_modules/@1password/sdk-core/nodejs/core_bg.wasm

#AWS lambda ric takes time to build. separating it into it's own build stage helps speed up the build
FROM us-west1-docker.pkg.dev/p0-prod/chainguard/p0.dev/p0-node:24.22.1-dev AS aws-build
ARG FUNCTION_DIR
USER root

RUN corepack enable yarn
# Build dependencies required for aws-lambda-ric native compilation
RUN apk update && apk add --no-cache cmake autoconf automake libtool python3 py3-setuptools
WORKDIR ${FUNCTION_DIR}
# npm v12 (shipped in the 24.18 Chainguard image via npm 12.0.0-pre; 24.16 was still on
# npm 11.x) default-denies dependency install scripts (allowScripts opt-in). aws-lambda-ric
# relies on an implicit node-gyp rebuild to compile the native rapid-client.node addon;
# without allow-listing it, npm install "succeeds" but skips the build, and the Lambda
# crashes at init with "Cannot find module './rapid-client.node'".
RUN printf 'allow-scripts[]=aws-lambda-ric\n' > .npmrc \
  && npm install aws-lambda-ric@4.0.2
# node-gyp is only needed while that install compiles rapid-client.node, yet
# it stays a dependency of the installed package, so the Lambda would ship it
# and the 90-odd packages only it needs (make-fetch-happen, http-cache-semantics,
# tar), which image scanners score. Drop it from the package's dependencies and
# let npm prune the rest. npm's hidden lockfile has to go or prune keeps them.
RUN node -e 'const f = "node_modules/aws-lambda-ric/package.json"; \
      const p = require("./" + f); delete p.dependencies["node-gyp"]; \
      require("fs").writeFileSync(f, JSON.stringify(p, null, 2));' \
  && rm -f package-lock.json node_modules/.package-lock.json \
  && npm prune --no-audit --no-fund \
  && test -f node_modules/aws-lambda-ric/rapid-client.node \
  && test ! -d node_modules/node-gyp

FROM us-west1-docker.pkg.dev/p0-prod/chainguard/p0.dev/p0-node:24.22.1
# Include global arg in this stage of the build
ARG WORKSPACE
ARG FUNCTION_DIR
ARG BUILD_DATE
ARG GIT_REF
ENV WORKSPACE=$WORKSPACE
ENV BUILD_DATE=$BUILD_DATE
ENV GIT_REF=$GIT_REF

# Set working directory to function root directory
WORKDIR ${FUNCTION_DIR}


COPY --from=aws-build ${FUNCTION_DIR} ${FUNCTION_DIR}
COPY --from=build /app/dist/index.mjs ${FUNCTION_DIR}
# The bundle imports the SDK on first use, from here.
COPY --from=build /app/node_modules/@1password ${FUNCTION_DIR}/node_modules/@1password
# npm in the Chainguard runtime pins ip-address 10.7.1, which is CVE-2026-111997
# (fixed in 10.7.4). node-gyp in the same base image bundles undici 8.11.2.
# aws-lambda-ric is already installed under /var/task, so drop both and invoke
# that binary. npx would keep the vulnerable tree.
USER root
RUN rm -rf /usr/lib/node_modules/npm /usr/lib/node_modules/node-gyp \
 && rm -f /usr/bin/npm /usr/bin/npx \
 && rm -f /var/lib/db/sbom/npm-*.spdx.json /var/lib/db/sbom/node-gyp-*.spdx.json
USER node

ENTRYPOINT ["/var/task/node_modules/.bin/aws-lambda-ric"]
CMD ["index.handler"]