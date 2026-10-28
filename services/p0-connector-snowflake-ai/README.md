# p0-connector-snowflake-ai

> **Beta.** This connector is in beta.

Snowflake (AI) connector: gives an AI agent temporary access to a Snowflake
account through its own minted identity, which reaches Snowflake's managed
MCP server.

For each grant, the connector mints a `TYPE = SERVICE_AGENT` user and a
wrapper role, both named `P0_AGENT_<request id>`. P0 chooses the name; the
connector refuses any user or role outside that namespace.

- `provisionUser` finds the user, or creates the wrapper role, grants it
  USAGE on the warehouse and on the install's MCP server object, creates the
  user, sets the install's authentication policy on it (token sign-in only,
  and no network policy needed), grants it the role, and adds a programmatic
  access token (PAT) restricted to the role. It writes the PAT to the secret
  P0 names, in the install's secret manager, and only then clears the user's
  "pending" comment. Each step has an undo, so a failed grant leaves nothing behind.
- `setPoliciesForUser` grants the requested access to the wrapper role. With
  no policies (revoke), it disables the user, which aborts running queries.
- `deleteUser` deletes the secret, then drops the role, then the user (and
  with it the PAT). Each step is a no-op when its object is already gone.
  The role is dropped as its own empty owner role, `P0_AGENT_<request
id>_OWNER`, because Snowflake gives a dropped role's objects to the role
  that drops it: whatever the agent created goes to a role that can do
  nothing and holds no other agent's leftovers. The owner role stays.
  The user goes last, so a revoke that fails partway is found and finished
  by its retry.
- A user still marked pending, or without its secret, is left by a grant
  or revoke that never finished. The lookup removes it and reports it missing, so a grant mints
  it afresh and a revoke sees it as already gone.
- `list` returns roles (`SHOW ROLES`), warehouses (`SHOW WAREHOUSES`), and
  databases, schemas, tables and views (`SNOWFLAKE.ACCOUNT_USAGE`, which lags
  new objects by up to about 90 minutes).
- `install.validation.get` checks the private key, the sign-in, that the
  connector's role holds USERADMIN and SECURITYADMIN, that `ACCOUNT_USAGE` is
  readable, and that the MCP server and the agents' authentication policy
  exist. A failure names its check
  in `payload.step`.

Two access types share this lifecycle:

- `role`: each policy is an existing customer role, granted to the wrapper
  role. No role is refused; P0 policies are the only guard.
- `objects`: each policy is one privilege (SELECT, INSERT, UPDATE or DELETE)
  on a database, schema, table or view. A database or schema entry covers the
  tables and views that exist when access is granted. Views get SELECT only.

The user and its PAT expire after the grant's length in whole days (at least
1, at most 365), even if P0's revoke never runs.

Every identifier in SQL is checked against a strict pattern and quoted, and
every string literal is escaped. Request input never reaches SQL any other
way. Neither the PAT nor the private key is logged: a secret manager error is
passed on without its cause, because the cause can carry the request body.
The token secret must be under the `p0_access-token_snowflake-ai_` prefix and
can't be the connector's own key secret.

## Sign-in

The connector signs in as the install's `TYPE = SERVICE` user, with the role
P0 sends (`P0_AI_CONNECTOR`), by key pair. It reads the private key from the
secret named by `privateKeySecretId`, in AWS Secrets Manager (on Lambda) or
Google Secret Manager (on Cloud Run). Its value is an unencrypted PKCS8 PEM.

The connector signs in only to an account identifier made of letters, digits,
`_` and `-`, so a request can't send its key-pair JWT to another host.

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
  --build-arg WORKSPACE=@p0security/p0-connector-snowflake-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-snowflake-ai-aws:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-snowflake-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-snowflake-ai-gcloud:dev .
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

docker tag p0-connector-snowflake-ai-aws:dev \
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

docker tag p0-connector-snowflake-ai-gcloud:dev \
  "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-snowflake-ai-gcloud:dev"

docker push "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-snowflake-ai-gcloud:dev"
```

## Deploying new connector image

If you already have a Lambda function set up (e.g. from installing Snowflake (AI) in P0),
go to the AWS Console and deploy the function from the newly pushed image.

If you already have a Cloud Run service set up instead, go to the GCP Cloud
Console and deploy a new revision from the newly pushed image.
