# P0 Connector Framework

**[`@p0security/connector-core`](packages/connector-core)** — the core library for building connectors.

**[`@p0security/connector-sdk`](packages/connector-sdk)** — the SDK for building a custom resource connector.

Custom resource connectors should only depend directly on `@p0security/connector-sdk`, not the core package.

## Releasing

Two kinds of release ship from this repo. The prefix of the release's git tag says which:

| Tag prefix  | Releases                                                            | Version is read from                                                  | Tag                |
| ----------- | ------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------ |
| `connector` | Every connector image, which reports this as `connectorVersion`     | All `services/*/package.json`                                         | `connector/vX.Y.Z` |
| `npm`       | `@p0security/connector-core` and `@p0security/connector-sdk` on NPM | `packages/connector-core` and `packages/connector-sdk` `package.json` | `npm/vX.Y.Z`       |

A release's version must be above every earlier tag with the same prefix, and is never compared with
the other prefix's tags. The bare `v0.0.x` tags predate prefixes and are not compared with anything.

You set the version in a pull request. The
[Release workflow](https://github.com/p0-security/connector/actions/workflows/release.yaml) then
checks it, ships it and tags it, and never writes files itself.

### 1. Set the version in a pull request

On a branch off `main`, set the new version.

- `connector`, every service at once:

  ```sh
  yarn workspaces foreach --all --include 'services/*' version 1.1.0
  ```

- `npm`, both packages together:

  ```sh
  yarn workspace @p0security/connector-core version 0.2.0
  yarn workspace @p0security/connector-sdk version 0.2.0
  ```

Open a pull request to `main` and merge it once it is reviewed and CI passes. The **Check release
versions** job fails if a tag prefix's `package.json` files disagree.

For a `connector` release, wait for the merge commit's
[Deploy run](https://github.com/p0-security/connector/actions/workflows/on-push-main.yaml) to
finish. It builds the images the release uses.

### 2. Start the release

In GitHub, open **Actions → Release → Run workflow**, keep **Use workflow from** on `main`, and fill
in:

- **tag-prefix**: `connector` or `npm`.
- **version**: the version the pull request set, such as `1.1.0`.
- **commit**: the pull request's merge commit. Left empty, it releases `main`'s tip.
- **dry-run**: tick it to run every check without publishing or tagging.

Or from a terminal:

```sh
gh workflow run release.yaml -f tag-prefix=connector -f version=1.1.0 -f commit=<merge commit>
```

### 3. What the workflow does

1. Checks that the run started from `main`, the commit is on `main`, every `package.json` for the tag
   prefix is at the version, and the tag is free and above the last tag with that prefix.
2. Runs the lint and test workflows at the commit.
3. Ships the release:
   - `connector`: confirms every image in [`docker.yaml`](.github/workflows/docker.yaml) is on Docker
     Hub at `sha-<7 hex>` of the commit, and lists each image's digest in the run summary for the app's
     release catalog. It builds nothing: the merge to `main` already did. `latest` does not move.
   - `npm`: builds and publishes `connector-core`, then `connector-sdk`.
4. Pushes the tag at the commit.

It creates no GitHub Release.

### When a release fails

Nothing is final until the tag exists, so most failures are fixed and run again with the same
version. To run again, open the Release run and choose **Re-run failed jobs**, or start a new run.

| Fails at                   | Cause                                                                                | Fix                                                                                |
| -------------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| Check the release          | The run did not start from `main`                                                    | Start it again from `main`. **commit** can still name an older `main` commit.      |
| Check the release          | A `package.json` is wrong, or the version is not above the last tag with that prefix | Fix it in a pull request, then release the new merge commit with the same version. |
| Lint or test               | A bug at that commit                                                                 | Merge a fix, then release the new merge commit with the same version.              |
| Check the connector images | The commit's Deploy run failed, or a later merge cancelled it                        | Release a later `main` commit whose Deploy run finished, with the same version.    |
| Publish to NPM             | One package published and the other did not                                          | Re-run failed jobs. A version already on NPM is skipped.                           |
| Publish to NPM             | The fix changes a package that is already on NPM                                     | NPM versions cannot be replaced. Set the next version in a pull request.           |
| Tag the release            | The push failed                                                                      | Re-run failed jobs. A tag already on the same commit counts as done.               |

Once a tag is pushed, never move or delete it. Fix a released bug in the next version.

### Repository settings

- The `NPM_AUTH_TOKEN` repository secret: an npm automation token with publish rights to the
  `@p0security` scope.
- The `docker-publish` environment, which already holds the Docker Hub secrets for `docker.yaml`. It
  only admits `main`, which is why a release must start from `main`.
- `github-actions[bot]` must be able to push `connector/v*` and `npm/v*` tags if a ruleset covers
  tags.

## License

Copyright © 2026-present P0 Security

This project is free software: you may redistribute it and/or modify it under the terms of the GNU
Lesser General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. See [LICENSE](LICENSE) and
[LICENSE.GPL](LICENSE.GPL).
