# P0 Connector Framework

**[`@p0security/connector-core`](packages/connector-core)** — the core library for building connectors.

**[`@p0security/connector-sdk`](packages/connector-sdk)** — the SDK for building a custom resource connector.

Custom resource connectors should only depend directly on `@p0security/connector-sdk`, not the core package.

## Publishing

1. Bump **both** packages to the same version and merge that to `main`:

   ```sh
   yarn workspace @p0security/connector-core version <new-version>
   yarn workspace @p0security/connector-sdk version <new-version>
   ```

2. [Create a GitHub release](https://github.com/p0-security/connector/releases/new) tagged with that
   version in the format `v<new-version>` (e.g. `v0.1.0`).

Publishing the release triggers [`.github/workflows/publish.yaml`](.github/workflows/publish.yaml),
which runs the full lint and test suites, verifies the versions, and publishes both packages.

**Requires the `NPM_TOKEN` repository secret** — an npm automation token with publish rights to the
`@p0security` scope.
