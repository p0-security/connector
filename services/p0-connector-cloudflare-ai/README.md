# p0-connector-cloudflare-ai

Cloudflare (AI) connector: gives an agent time-bound access to one
Cloudflare account through one account-owned API token per agent, which
holds only the permission groups the agent was granted.

The connector reads the account's install token from the customer's own
secret manager on every call, and calls `https://api.cloudflare.com/client/v4`
only. Each call from P0 names the account's `accountId` and the secret that
holds the install token, as `secret`. The secret holds the token itself, not
JSON.

## Install token

An account-owned API token on the account, made by a Super Administrator,
with exactly two permission groups:

- **Account API Tokens Edit** on the account: mint, change and delete grant
  tokens, and list permission groups.
- **Zone Read** on all zones of the account: map zone names to ids.

The token can give an agent any permission in the account except token
management, so protect it like a Super Administrator credential.

## Install validation

`install.validation.get` takes `{ accountId, secret }`, and checks, in this
order, that:

1. `secret`: the connector can read the install token from the secret.
2. `verify`: Cloudflare accepts the token on
   `GET /accounts/{account_id}/tokens/verify`, and says it is active.
3. `groups`: the token's own policies, from
   `GET /accounts/{account_id}/tokens/{token_id}`, allow both groups above on
   the account. Zone Read may be on all of the account's zones instead.

It returns `tokenId` and `otherGroups`, the names of any other groups the
token holds. Other groups pass, and P0 shows them as a warning. Every check
only reads. Nothing of the token is reported.

A failed check fails the call. The error's `payload.step` names the check.

## Grant tokens

The `permission` access is a resource root. Its user is the grant's secret,
in the same secret manager as the install token. The secret holds one grant
token, named `P0 <secret ref>`.

`setPoliciesForUser` takes one policy, `{ expiresOn, resources }`. Each
resource is `account`, `all-zones` or `zone` (by name), with permission group
ids. Each resource becomes one allow policy on the token; zone resources nest
under the account. A zone the account no longer has is left out, with a
warning. Then, by the tokens with the grant's name:

- None: mint one, then write its value to the secret. If the write fails,
  delete the token.
- One: `PUT` the policies and expiry. The secret doesn't change.
- More than one: mint and write as for none, then delete the old ones, so a
  failed delete leaves a valid token in the secret.
- No resources left (`{ resources: [] }`): delete them all.

`deleteUser` deletes every token with the grant's name, then the secret. If a
token delete fails, the secret stays for the retry.

## Errors

A failed Cloudflare call names the call by its route template and status,
never its URL, and never quotes Cloudflare's message. Cloudflare's error
codes go in `payload.codes`. A 429 isn't tried again: Cloudflare blocks the
account's calls for five minutes.

A mint refused with a 4xx whose message names a limit is taken as the
account's 500-token cap, and fails as a `validation_error`. Cloudflare
documents no code for the cap.

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
  --build-arg WORKSPACE=@p0security/p0-connector-cloudflare-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-cloudflare-ai-aws:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-cloudflare-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-cloudflare-ai-gcloud:dev .
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

docker tag p0-connector-cloudflare-ai-aws:dev \
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

docker tag p0-connector-cloudflare-ai-gcloud:dev \
  "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-cloudflare-ai-gcloud:dev"

docker push "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-cloudflare-ai-gcloud:dev"
```

## Deploying new connector image

If you already have a Lambda function set up (e.g. from installing Cloudflare (AI) in P0),
go to the AWS Console and deploy the function from the newly pushed image.

If you already have a Cloud Run service set up instead, go to the GCP Cloud
Console and deploy a new revision from the newly pushed image.
