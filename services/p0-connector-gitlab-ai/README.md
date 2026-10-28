# p0-connector-gitlab-ai

GitLab (Agentic) connector - enables access provisioning/deprovisioning for
GitLab projects on GitLab.com.

Each grant gets its own secret, and its own
[service account](https://docs.gitlab.com/user/profile/service_accounts/) in
the customer's top-level group. The service account is a direct member of each
granted project, with the granted role. The secret's value is one token of the
service account, with the `mcp` scope, named `P0 <secret ref>`, which is how
the connector finds it again. The service account's username is
`p0-grant-<hash of the secret ref>`.

A policy change updates the service account's project memberships. Membership
changes apply at once, also to an open MCP session. A revoke deletes the
service account, which revokes its token at once, and deletes the secret.

A consumer sends the token as `Authorization: Bearer <token>` to the GitLab MCP
server, `https://gitlab.com/api/v4/mcp`.

## Order of operations

The GitLab MCP server decides on a user's first call whether the user may
connect, and keeps that answer for at least 30 minutes. A user with no project
or top-level group membership is refused. So the connector adds the
memberships before it creates the token. Membership of a subgroup alone is not
enough.

## Admin token

The connector reads an admin token from the secret named by
`adminTokenSecretId`. The secret's value is the token itself.

The token belongs to a service account with the Owner role in the top-level
group, and has the `api` scope. On GitLab.com, only top-level group Owners can
manage service accounts, and the Owner who creates the admin service account
must have verified their identity.

To find a grant's existing memberships, the connector briefly creates a
`read_api` token of the grant's service account, and revokes it at once: only
an administrator can list another user's memberships.

The request context names the group by id or full path; the connector calls
`https://gitlab.com/api/v4` only.

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
  --build-arg WORKSPACE=@p0security/p0-connector-gitlab-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-gitlab-ai-aws:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-gitlab-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-gitlab-ai-gcloud:dev .
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

docker tag p0-connector-gitlab-ai-aws:dev \
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

docker tag p0-connector-gitlab-ai-gcloud:dev \
  "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-gitlab-ai-gcloud:dev"

docker push "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-gitlab-ai-gcloud:dev"
```

## Deploying new connector image

If you already have a Lambda function set up (e.g. from installing GitLab in P0),
go to the AWS Console and deploy the function from the newly pushed image.

If you already have a Cloud Run service set up instead, go to the GCP Cloud
Console and deploy a new revision from the newly pushed image.
