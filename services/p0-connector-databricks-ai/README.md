# p0-connector-databricks-ai

Databricks (AI) connector. It lets an agent in a P0 agentic session reach Databricks data
through Databricks-hosted MCP servers, as a service principal P0 creates for that grant
alone, in one or more Databricks accounts.

Ships only as an AWS Lambda container image, named `p0-connector-databricks-ai`, outside any
VPC.

## Authentication

The connector holds no secret. For each call it mints an AWS outbound identity token for its
own execution role (`sts:GetWebIdentityToken`, audience `databricks`, on the regional STS
endpoint) and exchanges it at `<accountsUrl>/oidc/accounts/<accountId>/v1/token` for a token
for the service principal whose `application_id` the request names (RFC 8693 token exchange,
`scope=all-apis`). That principal is P0's own, one per Databricks account, and every one of
their federation policies trusts the same Lambda role. Tokens are cached per account and
principal until shortly before they expire. The AWS token lives for 15 minutes, and the
Databricks token inherits that lifetime.

The AWS account must have outbound web identity federation enabled, and the Lambda role must
be allowed `sts:GetWebIdentityToken`.

Requests are only ever sent to Databricks hosts. `accountsUrl` must be the commercial account
console on AWS, and a workspace host must be on its workspace domain (see
`src/databricks/context.ts`). Azure and GCP aren't accepted, since only AWS is checked. The
connector never follows a redirect, so a 307 or 308 can't resend a request, or the token in
it, to another host.

Nobody enters a workspace URL. The connector looks the workspace up in the account workspaces
API (`GET /api/2.0/accounts/<accountId>/workspaces/<workspaceId>`), which has no host field,
and builds `https://<deployment_name>.<domain>` from it, where `<domain>` is the workspace
domain of the account console it called. It refuses a workspace that isn't `RUNNING`, and a
host that isn't a Databricks workspace origin (see `src/databricks/workspaces.ts`).

## Install validation

`databricks-ai.install.validation.get` is what install validation runs, every hour, so it
never writes. It exchanges a token for P0's principal, which proves its federation policy
trusts the connector's role. Then it runs the checks its input asks for, each failing with a
message that says what to change:

- `requireAccountAdmin`: account SCIM lists `account_admin` in the principal's `roles`.
- `requireMetastoreAdmin`: P0's principal owns every metastore in the account
  (`GET /api/2.0/accounts/<accountId>/metastores`), itself by its application ID, or through
  a group named as the owner that lists the principal as a direct member. Nested groups don't
  count. A metastore with no owner fails. Every failure names the metastore.
- `ownerPrincipal`: the value names exactly one principal in account SCIM, a group by its
  display name, a user by their `userName`, or a service principal by its application ID.

`databricks-ai.install.validation.probe` writes, so it runs only when the account is saved. It
looks the given workspace up, makes P0's principal an admin of it through the account-level
permission assignment API (read first, and written only when `ADMIN` is missing), then starts
an MCP session with the workspace's Databricks SQL MCP server on Unity Gateway
(`/ai-gateway/mcp-services/system.ai.dbsql`): `initialize`, the `initialized` notification,
then `tools/list`. It reads only each answer's status. A 2xx means the Unity Gateway beta
is on, and a 404 means it's off. Anything else fails the probe, so neither an outage nor a
refusal reads as the beta being off. A 401 or 403 fails with a message to check that `account
users` still hold the default `EXECUTE` on the `system.ai` schema, or, right after P0 became
workspace admin, to try again in a few minutes.

## Agent principals

Each grant gets its own account service principal, named `p0-agent-<request id>`. The
connector acts only on principals with a name of that shape (`src/agent/name.ts`), matched
exactly, and never on P0's own principal.

`databricks-ai.install.principal.stage` runs when P0 stages the request. It finds the principal
by display name in account SCIM, or creates it, active and holding nothing, and returns its
application ID. Only stage creates principals. A grant whose principal is missing, or has
another application ID, is refused with a message that says to make the request again.

A grant then sets the principal up (`src/agent/agent.ts`). P0's principal becomes workspace
admin, which is never undone. The agent principal is assigned to the workspace as a user. A
workspace can take a while to list a newly assigned principal, so the grant looks for it again
for up to 60 seconds. The principal then gets the `workspace-consume` and
`databricks-sql-access` entitlements, which are read back, and
gets one federation policy last, `p0-databricks`. That policy trusts P0's auth server as
issuer, for the requesting session's subject on the MCP server it requested through, with the
account ID as audience. A step that fails undoes the ones before it, which leaves the bare
principal. It can't get a token without its policy.

A principal is finished when it holds its policy. An active one without it is cleaned up and
reported missing, so the next grant sets it up again. An inactive one is always found, so a
revoke that failed partway is finished by its retry. Deleting removes the policies, then the
principal.

## Data access

`databricks-ai.accesses.data` is a resource-root access whose user is the agent principal.

A grant gives the principal `CAN_USE` on the request's SQL warehouse and the request's Unity
Catalog privileges, catalog first. Every policy must be one of the request's `addedGrants`, and
P0's own principal is refused. It reads everything back and fails on a mismatch. Nothing is
granted on the MCP services: Databricks doesn't expose the `system.ai` ones as grantable
securables, and agents call them through the `EXECUTE` that `account users` hold on the
`system.ai` schema by default. The warehouse and Unity Catalog grants decide what an agent
reaches.

A revoke deactivates the principal, removes the `addedGrants`, then hands every table, view,
volume and function the principal owns under the securable to the owner principal.
Deactivation stops new token exchanges within about 78 seconds. The token the agent already
holds keeps working until it expires, up to about 15 minutes, with its grants already removed.
The transfer runs only when the `addedGrants` hold a `CREATE_*` privilege, since nothing else
lets the agent own anything. Revoking comes before the transfer, so a failed transfer can't
leave a grant in place. A failed step doesn't stop the rest. Revoke works on a workspace in any
status, since the grants are on the metastore. A deleted workspace fails the revoke, with a
message saying how a metastore admin finishes it by hand, from another workspace on the same
metastore: hand anything the principal owns to the owner principal, revoke every privilege it
holds, then delete the principal.
`deleteUser` runs the revoke again before it deletes anything, so a failed transfer stops the
delete and the revoke can be retried. `CAN_USE` on the warehouse stays until the principal is
deleted, because removing one entry means rewriting the warehouse's whole access list. Whether
Databricks drops a deleted principal's entry from that list isn't documented.

The listings are the account's running workspaces (`<name> (<host>)`), one workspace's host,
and in a workspace its pro and serverless SQL warehouses, its catalogs, and their schemas,
tables and volumes. The `system` and `__databricks_internal` catalogs are never listed. Every
listing inside a workspace makes P0's principal its admin first. A workspace can take a while
to see a new admin assignment, so right after one, a listing it refuses with a 401 or 403 is
tried again for up to 30 seconds. Then it fails with a message to try again in a few minutes.

## Unverified facts

INT-810 checks these in a test account. Each sits behind one function marked `TODO(INT-810)`:

- Unity Gateway answers a 404 when the Unity Gateway beta is off (`betaAnswer` in
  `src/install/probe.ts`). The live check had no account with the beta off.
- A metastore admin's `PATCH` of `owner` moves a volume or function to the owner principal
  (`setOwner` in `src/accesses/data/unity-catalog.ts`). The live check saw it move a table.

## Creating local builds

The build pulls P0's base images from a private GCP Artifact Registry, so log in and register
gcloud as a Docker credential helper for that host first. This is required even though the
connector itself deploys to AWS:

```bash
gcloud auth configure-docker us-west1-docker.pkg.dev
```

Then run this from the repository root:

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/lambda/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-databricks-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-databricks-ai:dev .
```

This will set your locally-built images to have the tag `dev`.

## Tests

The tests run from the repository root, as CI runs them. Run `yarn :show-lockfile` and
`yarn install` first (see the root README's lockfile section). Build the monorepo before
testing, because the connector imports the built `@p0security/connector` package:

```bash
yarn :build
yarn :test services/p0-connector-databricks-ai
yarn workspace @p0security/p0-connector-databricks-ai typecheck
```

The tests stub Databricks and AWS STS (`src/__tests__/http.ts`, `src/__tests__/databricks.ts`
and `src/__tests__/sts.ts`), so they never call either.

## Trying a change in a dev install

P0 always invokes the deployed Lambda, so to try a change, deploy an image built from your
branch to the connector of a dev install.

The connector's Terraform creates the ECR repository with immutable tags, so each push needs a
tag of its own. Build the image as above, then push it and point the Lambda at it:

```bash
AWS_ACCOUNT_ID="your-aws-account-id"
AWS_REGION="your-aws-region"
REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/p0-connector-databricks-ai"
TAG="dev-$(date +%s)"

aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "${REPO%%/*}"

docker tag p0-connector-databricks-ai:dev "$REPO:$TAG"
docker push "$REPO:$TAG"

aws lambda update-function-code --region "$AWS_REGION" \
  --function-name p0-connector-databricks-ai --image-uri "$REPO:$TAG"
```

The next `terraform apply` of the connector puts the pinned image back. Its logs are in
CloudWatch, in `/aws/lambda/p0-connector-databricks-ai`.

## Releasing

A pull request builds the image but doesn't push it. Each merge to `main` pushes it to Docker
Hub as `p0security/p0-connector-databricks-ai:sha-<short commit>`
(`.github/workflows/docker.yaml`). New installs get the image the app's Databricks (AI)
installer pins, so a release only reaches customers once the app bumps that pin. If the change
alters the connector's API, the same app PR bumps `submodules/security-perimeter`.
