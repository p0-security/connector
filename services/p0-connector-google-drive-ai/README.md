# p0-connector-google-drive-ai

Google Drive (Agentic) connector — grants and revokes time-boxed access to a single folder
or file inside a customer's shared drive.

Ships only as a GCP Cloud Run container image.

## What it does

One resource-root access type, `resource`. The grantee is the short-lived
service account P0 mints per agentic session, never the human who asked for the
access; the grant is a single `permissions.create` on the requested item, at
`reader` or `writer`.

Two properties are worth knowing before reading the code:

- **The connector holds no credential of its own.** Its Cloud Run service
  identity _is_ the admin service account, which a human has already made an
  `organizer` on each registered shared drive. Everything runs on Application
  Default Credentials, with no impersonation anywhere.
- **A shared drive itself is never a grant target.** A permission written on a
  drive id is a membership mutation, and Drive will then silently swallow a
  concurrent grant on a folder inside that drive. Only folders and files inside
  a registered drive can be granted.

## Creating local builds

The build pulls P0's base images from a private Artifact Registry, so log in and
register gcloud as a Docker credential helper for that host first:

```bash
gcloud auth configure-docker us-west1-docker.pkg.dev
```

Then run this from the repository root:

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-google-drive-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-google-drive-ai:dev .
```

## Deploying

The service account the Cloud Run service runs as needs the
`https://www.googleapis.com/auth/drive` scope and `organizer` on every shared
drive the install registers. Granting it that membership is a manual Workspace
step, by design: automating it would need a domain-admin privilege P0 is not
willing to hold.
