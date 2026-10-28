# p0-connector-cloudsql

GCP CloudSQL connector - enables access provisioning/deprovisioning for

- CloudSQL: uses GCP APIs
- Postgres: provisions directly within a P0-managed Postgres instance
- MySQL: provisions directly within a P0-managed MySQL instance

## Creating local builds

The build pulls P0's base images from a private Artifact Registry, so log in and register
gcloud as a Docker credential helper for that host first:

```bash
gcloud auth configure-docker us-west1-docker.pkg.dev
```

Then run this from the repository root:

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-cloudsql \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-cloudsql:dev .
```

This will set your locally-built images to have the tag `dev`.

## Publishing local builds to GCP (Artifact Registry)

Fill in the placeholders for your own GCP project/testing environment:

```bash
GCP_PROJECT_ID="your-gcp-project-id"
GCP_REGION="your-gcp-region"
GCP_ARTIFACT_REPOSITORY="your-artifact-registry-repo-name"
```

The `$GCP_ARTIFACT_REPOSITORY` repository must already exist in Artifact
Registry, and you must have permission to push images to it, before running the commands below.

You push to your own registry host, `$GCP_REGION-docker.pkg.dev`, which may be a different host
from the `us-west1-docker.pkg.dev` one the base images come from. It needs its own credential
helper entry; passing both at once covers the build and the push.

Tag the locally-built image with the correct destination.

```bash
gcloud auth configure-docker "$GCP_REGION-docker.pkg.dev"

docker tag p0-connector-cloudsql:dev \
  "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-cloudsql:dev"

docker push "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-cloudsql:dev"
```

## Deploying new connector image

If you already have a Cloud Run service set up (e.g. from installing MySQL or Postgres in P0),
go to the GCP Cloud Console and deploy a new revision from the newly pushed image.
