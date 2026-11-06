# p0-connector-gitguardian-ai

GitGuardian (Agentic) connector. It gives an agent a GitGuardian API token
with the scopes its requester asked for, and revokes the token when the grant
ends.

Each grant gets its own secret, which holds one token. The secret's value is
the token itself. The token belongs to the owner of the customer's admin token
(a dedicated connector member, or a service account on paid plans), holds only
the granted scopes, and is named `P0 <hash> <unix seconds>`. `<hash>` is the
first 16 hex characters of the SHA-256 of the secret's ref.

GitGuardian can't change a token's scopes or lifetime, so every policy change
mints a new token, writes it to the secret, and then revokes the old one. A
revoke revokes the token and deletes the secret. The token's lifetime covers
the requester's longest open grant, rounded up to whole days, or 365 days when
a grant has no end. The policy carries that end time as `grantEndsAt`, because
the control plane builds the policy from every open grant. The revoke is what removes access. The lifetime is a
backstop.

A consumer sends the token as `Authorization: Bearer <token>` to GitGuardian's
hosted MCP server.

## Admin token

The connector reads the admin token from the secret named by
`adminTokenSecretId`. Its value is the token as plain text. Leading and
trailing whitespace is ignored.

The admin token must hold:

- `api_tokens:write`, to revoke grant tokens
- `api_tokens:read`, to find a grant's tokens again
- every scope a grant may ask for (`scan`, `incidents:read`,
  `incidents:write`, `sources:read`, `members:read`), because a minted token
  can hold only scopes its caller holds

The install `validation` route checks the first two with
`GET /v1/api_tokens/self`, along with the token's workspace and region.

The request context names the workspace's region, `us` or `eu`. The connector
calls `https://api.gitguardian.com` or `https://api.eu1.gitguardian.com`, and
no other host.

## Finding a grant's tokens

The connector can write a grant secret but never read it back: its cloud role
has no `secretmanager.versions.access` on grant secrets. So it finds a grant's
tokens by listing the admin token owner's active tokens and keeping the ones
named `P0 <hash> `. It never touches the admin token or a token without that
prefix.

## What the connector logs

`setPoliciesForUser` returns nothing to P0, so the connector's log is the
record of each token:

- `minted GitGuardian token and stored it in the secret`: the token id, the
  scopes GitGuardian returned, its expiry, and the lifetime in days
- `GitGuardian token already gone`: a token that was revoked before P0 revoked
  it, for example by an agent with the MCP's `revoke_current_token`
- `old token revoke failed`: a change succeeded, but its old token is still
  valid until it expires

A failed revoke at the end of a grant is not only logged. It fails the call,
so P0 marks the grant as revoke failed.

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
  --build-arg WORKSPACE=@p0security/p0-connector-gitguardian-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-gitguardian-ai-aws:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-gitguardian-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-gitguardian-ai-gcloud:dev .
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

docker tag p0-connector-gitguardian-ai-aws:dev \
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

docker tag p0-connector-gitguardian-ai-gcloud:dev \
  "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-gitguardian-ai-gcloud:dev"

docker push "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-gitguardian-ai-gcloud:dev"
```

## Deploying new connector image

If you already have a Lambda function set up (e.g. from installing GitGuardian in P0),
go to the AWS Console and deploy the function from the newly pushed image.

If you already have a Cloud Run service set up instead, go to the GCP Cloud
Console and deploy a new revision from the newly pushed image.
