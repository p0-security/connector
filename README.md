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

**Requires the `NPM_AUTH_TOKEN` repository secret** — an npm automation token with publish rights to the
`@p0security` scope.

Both packages stay on `0.x`. Connector image releases (below) share the `v*` tag namespace and start at
`v1.1.0`, so the two never collide.

## Releasing connector images

Every merge to `main` builds every connector image and tags it `sha-<7 hex>` and `latest`. A
connector release is a git tag `vX.Y.Z` on a **release commit**: a commit that sets every
`services/*/package.json` to `X.Y.Z`, so each image built from it reports `connectorVersion: X.Y.Z`.
Images get no version tag. A release's images are the ones tagged `sha-<release commit>`, and pins
name them as `sha-<release commit>@sha256:<digest>`.

To release, run the [Release workflow](https://github.com/p0-security/connector/actions/workflows/release.yaml)
from `main` with the version, `x.y.z`. [`.github/workflows/release.yaml`](.github/workflows/release.yaml)
then:

1. Checks the version: plain `x.y.z` (no prereleases), its `v` tag free, above every `v*` tag and
   above the version `main`'s services already report. It also refuses to start while a `release/*`
   branch exists, which is a release still running or a failed one.
2. Writes the version into all `services/*/package.json` files, commits that as the release commit on
   a new `release/x.y.z` branch, and starts a second run of the workflow on that branch. The root
   `package.json` stays at `0.0.0`, and `packages/*` are untouched.
3. Runs the lint and test workflows at the release commit.
4. Builds and pushes every image through [`docker.yaml`](.github/workflows/docker.yaml) on the
   release branch, so each is tagged `sha-<release commit>`. `latest` does not move: it only moves on
   `main`.
5. Reads the version back from every service, fails unless they all match, pushes the `vX.Y.Z` tag at
   the release commit and deletes the release branch. It creates no GitHub Release, since that would
   start [`publish.yaml`](.github/workflows/publish.yaml), the NPM publish.
6. Opens a PR against `main`, from `version-bump/x.y.z`, that writes the same version onto `main`.
   **Merge it**: until it lands, builds from `main` (and `latest`) report the previous version. A PR
   opened by a workflow starts no checks, so close and reopen it to run lint and test.

If a job fails after the release branch is pushed, re-run the failed jobs of the run on
`release/x.y.z`. Every step can be re-run. To abandon a release instead, delete its `release/x.y.z`
branch (and its `vX.Y.Z` tag, if `promote` pushed one before failing).

### One-time settings

The release run needs these repository settings, which are not in code:

- The `docker-publish` environment must allow deployments from `release/*` as well as `main`. It
  holds the Docker Hub secrets, so without it the image build fails at the Docker Hub login.
- **Settings → Actions → General → Workflow permissions** must allow GitHub Actions to create pull
  requests, or the version-bump PR step fails.
- Any ruleset on branches or tags must let `github-actions[bot]` create `release/*` and
  `version-bump/*` branches, delete `release/*` branches and push `v*` tags.

The Google workload identity provider that `docker.yaml` uses (`github-actions-provider` in
`p0-prod`, managed in `infra`) admits any `p0-security` repository and binds the service account by
repository, not by branch, so it needs no change.

## License

Copyright © 2026-present P0 Security

This project is free software: you may redistribute it and/or modify it under the terms of the GNU
Lesser General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. See [LICENSE](LICENSE) and
[LICENSE.GPL](LICENSE.GPL).
