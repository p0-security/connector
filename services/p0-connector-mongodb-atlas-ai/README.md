# p0-connector-mongodb-atlas-ai

MongoDB Atlas (Agentic) connector - enables access provisioning/deprovisioning
for Atlas project roles through the Atlas-hosted MCP server
(`https://mcp.mongodb.com/`).

Each grant gets its own secret that holds one access token for the hosted MCP
server. The secret's value is the token itself. The token belongs to an Atlas
[MCP configuration](https://www.mongodb.com/docs/mcp-server/remote-mcp/access-models/)
that the connector creates in the project for the grant, named `p0-<hash>` from
the grant's secret. Its policies are the configuration's project roles, such as
`GROUP_DATA_ACCESS_READ_ONLY`; Atlas enforces them on every tool call.

A policy change sets the configuration's roles, then rotates its secret: the
connector creates a new configuration secret, gets a token with the client
credentials grant, writes the token as a new secret version, and then deletes
the configuration's older secrets. Deleting a configuration secret ends its
tokens at once. A configuration holds at most 2 secrets.

A revoke deletes the configuration with its secrets, which ends its tokens at
once, and then deletes the grant's secret.

Atlas access tokens last 1 hour, and nothing renews the token in the grant's
secret.

A consumer sends the token as `Authorization: Bearer <token>` to the hosted MCP
server.

## Admin service account

The connector acts as an Atlas service account with the Project Owner role in
the project, whose client ID is `clientId`. It reads the service account's
client secret from the secret named by `clientSecretSecretId`. Its value is the
client secret itself.

If the organization requires an IP access list for the Atlas Administration
API, the service account's access list must allow the connector's egress
addresses.

Configuration secrets last 8 hours, the shortest lifetime that Atlas allows by
default. If the organization raises the minimum, Atlas refuses the secret.

Ships as both an AWS Lambda container image and a GCP Cloud Run container
image, built from the same workspace with two different Dockerfiles.

## Creating local builds

Both images pull P0's base images from a private GCP Artifact Registry, so log in and register
gcloud as a Docker credential helper for that host first. This is required for the AWS Lambda
image too:

```bash
gcloud auth configure-docker us-west1-docker.pkg.dev
```

Then run these from the repository root:

### AWS Lambda

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/lambda/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-mongodb-atlas-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-mongodb-atlas-ai-aws:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-mongodb-atlas-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-mongodb-atlas-ai-gcloud:dev .
```

This will set your locally-built images to have the tag `dev`.

## Publishing local builds

### AWS (ECR)

Fill in the placeholders for your own AWS project/testing environment:

```bash
AWS_ACCOUNT_ID="your-aws-account-id"
AWS_REGION="your-aws-region"
AWS_ECR_REPOSITORY="your-ecr-repository-name"
```

The `$AWS_ECR_REPOSITORY` repository must already exist in ECR, and you must have permission
to push images to it, before running the commands below.

Make sure the AWS CLI has credentials for that account, then let
`aws ecr get-login-password` hand a short-lived token to `docker login`.

Tag the locally-built image with the correct destination.

```bash
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

docker tag p0-connector-mongodb-atlas-ai-aws:dev \
  "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$AWS_ECR_REPOSITORY:dev"

docker push "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$AWS_ECR_REPOSITORY:dev"
```

### GCP (Artifact Registry)

Fill in the placeholders for your own GCP project/testing environment:

```bash
GCP_PROJECT_ID="your-gcp-project-id"
GCP_REGION="your-gcp-region"
GCP_ARTIFACT_REPOSITORY="your-artifact-registry-repo-name"
```

The `$GCP_ARTIFACT_REPOSITORY` repository must already exist in Artifact
Registry, and you must have permission to push images to it, before running the commands below.

You push to your own registry host, `$GCP_REGION-docker.pkg.dev`, which is a different host
from the `us-west1-docker.pkg.dev` one the base images come from. It needs its own credential
helper entry; passing both at once covers the build and the push.

Tag the locally-built image with the correct destination.

```bash
gcloud auth configure-docker "$GCP_REGION-docker.pkg.dev"

docker tag p0-connector-mongodb-atlas-ai-gcloud:dev \
  "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-mongodb-atlas-ai-gcloud:dev"

docker push "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-mongodb-atlas-ai-gcloud:dev"
```

## Deploying new connector image

If you already have a Lambda function set up (e.g. from installing MongoDB Atlas in P0),
go to the AWS Console and deploy the function from the newly pushed image.

If you already have a Cloud Run service set up instead, go to the GCP Cloud
Console and deploy a new revision from the newly pushed image.
