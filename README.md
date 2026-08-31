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

## License

Copyright © 2026-present P0 Security

This project is free software: you may redistribute it and/or modify it under the terms of the GNU
Lesser General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. See [LICENSE](LICENSE) and
[LICENSE.GPL](LICENSE.GPL).
