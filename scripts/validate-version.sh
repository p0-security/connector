#!/usr/bin/env bash
# Validates the version to publish and prints it (without a leading "v") to
# stdout, so callers can capture it into a step output.
#
# Inputs (env):
#   PKG_VERSION  version from packages/connector-core/package.json
#   EVENT_NAME   github.event_name ("release" or "workflow_dispatch")
#   VERSION      github.event.release.tag_name (release) or
#                inputs.version (workflow_dispatch)
set -euo pipefail

RELEASE_RE='^[0-9]+\.[0-9]+\.[0-9]+$'
PRERELEASE_TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+-[0-9A-Za-z.-]+$'

if ! [[ "$PKG_VERSION" =~ $RELEASE_RE ]]; then
  echo "::error::Version $PKG_VERSION is not in major.minor.patch format. Package versions must be plain semver, e.g. 1.2.3." >&2
  exit 1
fi

case "$EVENT_NAME" in
  release)
    if [ "$VERSION" != "v$PKG_VERSION" ]; then
      echo "::error::Release tag $VERSION does not match package version v$PKG_VERSION." >&2
      exit 1
    fi
    echo "$PKG_VERSION"
    ;;
  workflow_dispatch)
    if ! [[ "$VERSION" =~ $PRERELEASE_TAG_RE ]]; then
      echo "::error::Version $VERSION is not a valid pre-release version, e.g. v0.26.1-alpha.0." >&2
      exit 1
    fi
    echo "${VERSION#v}"
    ;;
  *)
    echo "::error::Unsupported event $EVENT_NAME." >&2
    exit 1
    ;;
esac
