# p0-connector-pagerduty-ai

PagerDuty (Agentic) connector - enables access provisioning/deprovisioning for
PagerDuty OAuth scopes.

Each grant gets its own secret that holds one PagerDuty
[app token](https://docs.pagerduty.com/developer/private-apps). The secret's
value is the token itself. The connector gets the token from the customer's
Scoped OAuth app with the client credentials grant. The token holds only the
requested scopes, in the one account named by `as_account-<region>.<subdomain>`,
and acts as the app, not as a user.

A token's scopes cannot change, so a policy change gets a new token and writes
it as a new secret version. A revoke deletes the secret. PagerDuty documents no
way to revoke one app token, so a replaced or deleted token stays valid until
it expires, 1 day after it was issued. An open grant needs a new token before
then.

A consumer sends the token as `Authorization: Bearer <token>`, both to the
PagerDuty API and to the PagerDuty MCP server.

## Client secret

The connector reads the Scoped OAuth app's client secret from the secret named
by `clientSecretSecretId`. Its value is the client secret itself.

The app's scopes limit which scopes a token can hold, so give the app only the
scopes that P0 may grant. The app must also hold `users.read`: the connector
adds it to every token, because PagerDuty's MCP server refuses a token without
it. PagerDuty leaves out a requested scope that the app does not hold, without
an error, so the connector fails the grant when the token lacks a requested
scope.

The scope picker lists the `scopes_supported` that PagerDuty's MCP server
publishes for the account's region
(`https://mcp.pagerduty.com/.well-known/oauth-protected-resource/mcp`, or
`mcp.eu.pagerduty.com` for EU). PagerDuty has no API that lists an app's own
scopes.

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
  --build-arg WORKSPACE=@p0security/p0-connector-pagerduty-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-pagerduty-ai-aws:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-pagerduty-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-pagerduty-ai-gcloud:dev .
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

docker tag p0-connector-pagerduty-ai-aws:dev \
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

docker tag p0-connector-pagerduty-ai-gcloud:dev \
  "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-pagerduty-ai-gcloud:dev"

docker push "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-pagerduty-ai-gcloud:dev"
```

## Deploying new connector image

If you already have a Lambda function set up (e.g. from installing PagerDuty in P0),
go to the AWS Console and deploy the function from the newly pushed image.

If you already have a Cloud Run service set up instead, go to the GCP Cloud
Console and deploy a new revision from the newly pushed image.
