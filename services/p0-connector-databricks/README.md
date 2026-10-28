# p0-connector-databricks

Databricks connector - grants and revokes Unity Catalog privileges, workspace admin and
account admin for P0 users, in one or more Databricks accounts.

Ships only as an AWS Lambda container image, named `p0-connector-databricks`, outside any VPC.

## Authentication

The connector holds no secret. For each call it mints an AWS outbound identity token for its
own execution role (`sts:GetWebIdentityToken`, audience `databricks`, on the regional STS
endpoint) and exchanges it at `<accountsUrl>/oidc/accounts/<accountId>/v1/token` for a token
for the service principal whose `application_id` the request names (RFC 8693 token exchange,
`scope=all-apis`). Each Databricks account has its own service principal, and every one of
their federation policies trusts the same Lambda role. Tokens are cached per account and
principal until shortly before they expire. The AWS token lives for 15 minutes, and the
Databricks token inherits that lifetime.

The AWS account must have outbound web identity federation enabled, and the Lambda role must
be allowed `sts:GetWebIdentityToken`.

Requests are only ever sent to Databricks hosts: `accountsUrl` must be one of the account
consoles and a workspace URL must be on a Databricks workspace domain (see
`src/databricks/context.ts`). The connector never follows a redirect, so a 307 or 308 can't
resend a request, or the token in it, to another host.

P0 sends each workspace's URL with its numeric ID: the customer enters the URL when they
install the workspace. Before an access type makes any other call to a workspace, the
connector binds the URL to the ID. It asks the workspace for its Unity Catalog metastore
assignment (`GET <workspaceUrl>/api/2.1/unity-catalog/current-metastore-assignment`) and
refuses the call unless the `workspace_id` there is the ID P0 sent. So a wrong or stale URL
can't act in another workspace. The connector caches the answer per principal and URL for the
life of the Lambda instance, and compares the requested ID on every call (see
`src/databricks/workspaces.ts`). A workspace without a metastore can't be bound, so it can't
be installed. New Databricks workspaces get one automatically.

The `privilege` lister's `metastore` query returns the metastore ID the binding read.

Install validation exchanges a token for the service principal, which proves its federation
policy trusts the connector's role. It calls an account API only when asked to confirm
account admin. Given a workspace, it calls the workspace's `SCIM /Me` first, so a principal
the workspace refuses gets a message about its assignment. A successful `/Me` proves the
principal is assigned there. Then it binds the URL, and reports whether `/Me` lists the
workspace's `admins` group.

`privilege` never looks a user up. It grants to the requestor's email, which is their
Databricks username and the `principal` a Unity Catalog grant names, and it calls only the
token endpoint and the workspace. P0 records that email at stage as `userName`, and a revoke
names the same string, which no Databricks API can change. The user ID parser refuses
anything that isn't an email, so a bare group name or a service principal's application ID
never reaches Databricks, and the connector can't name its own principal. When Databricks
doesn't know the email, a grant fails with an error that says to add the user, and a revoke
counts as done, since that principal holds nothing.

`admin` acts in one of two scopes. A request context or lister query that carries a
`workspaceId` and `workspaceUrl` names workspace admin on that workspace, and one that carries
neither names account admin. The parsers refuse one without the other, and so does the
handler, so half a pair never reaches the account scope.

- **Workspace admin** binds the workspace first, then uses only workspace APIs, which a
  workspace admin can call: the workspace's proxy of account SCIM
  (`<workspaceUrl>/api/2.0/account/scim/v2/Users`) to find the user, and the workspace's own
  permission assignment API (`/api/2.0/preview/permissionassignments`) to read, set and remove
  their assignment.
- **Account admin** uses account SCIM `Users` and the user's `roles`, which need account admin.

Both read account SCIM users, which never include a group or service principal and still list
a user who has been unassigned from every workspace. P0 can name a user by the account SCIM
`userId` it recorded at stage, so revoke doesn't depend on matching an email that may have
changed. Otherwise the requestor's email is matched to a `userName`, and only when none
matches, to the `emails` of exactly one user. A `userName` can be an email or a Microsoft
Entra UPN, such as a guest's `alice_example.com#EXT#@contoso.onmicrosoft.com`, whose domain is
the part after the `@`. A user who no longer exists is reported as gone. As defence in depth,
the connector also refuses to act on its own service principal: in a workspace, the one that
workspace's `SCIM /Me` reports, and for the account, the one account SCIM finds by application
ID. Databricks refusing a call in either scope with a 403 fails it with a message that says
which role P0's principal lacks, and how to give it.

## Environment

| Variable         | Set by            | Meaning                                                                                                                                                        |
| ---------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DOMAIN_PATTERN` | install terraform | `domainPattern`: the regex for domain verification, matched against the whole domain of a user's Databricks `userName`, ignoring case. Unset refuses everyone. |
| `AWS_REGION`     | Lambda runtime    | Region of the STS endpoint used to mint the identity token.                                                                                                    |

Domain verification checks every user's Databricks `userName`, never the `emails` an IdP or
admin can edit. It gates every lookup that resolves a user from an email, and every grant,
even one that finds nothing left to add. It never refuses a revoke: P0 recorded the user's
identity at stage, after they passed, so a revoke goes ahead even if the user no longer
passes because the pattern narrowed or is unset or invalid. The connector then logs one
warning, and the revoke only ever removes access. So a narrowed or misconfigured pattern
blocks new grants but never a revoke. Install validation fails while `DOMAIN_PATTERN` is
unset or not a valid regex.

## Grants and revokes

Every call to an access type says in its request context whether it is part of a grant or a
revoke (`operation`: `grant` or `revoke`), which P0 sets from the request's status. The
policies alone can't tell: a revoke whose grants an open sibling request still holds removes
nothing, just like a grant. Nor can `operation` alone: when a grant fails partway, P0 rolls it
back with calls that still say `grant`. So a call that removes access is a revoke, whatever
`operation` says. Only a rollback should say `grant` and remove access, so the connector logs a
warning whenever it takes a call labeled `grant` for a revoke.

For `privilege`, a call is a revoke when `operation` says so or when its `requestGrants` aren't
all in its `policies`. A grant whose `policies` name a privilege P0 doesn't grant is refused.
A revoke's `policies` may name one, since an open sibling's stored grant can after P0 stops
granting a privilege: the revoke leaves it in place, and never adds it back. A revoke for a
user who no longer passes domain verification removes this request's grants and adds nothing
back. A revoke removes this request's grants first, leaves first, and only then repairs a
grant it shares with an open sibling. It attempts every call even when one fails, and then
fails with the first error, since P0 runs a failed grant's rollback only once. On a revoke, a
securable that no longer exists counts as done for every grant on it, and an email that names
no Databricks principal counts as done for the whole call. On a grant either fails. A revoke
can't go through a workspace it can't bind, such as one deleted since stage, but its grants
live on the metastore and outlive the workspace. So when a revoke that removes grants can't
bind its workspace, it fails naming the grants to remove by hand.

For `admin`, a call is a revoke when `operation` says so or when its `policies` are empty,
since a call without the scope's role can only lower access. A grant carries the role, and is
verified even when the user already holds it. A revoke whose policies still carry the role,
because another open request on the scope holds it, changes nothing. Otherwise it removes
`account_admin`, or, only while the user is still workspace `ADMIN`, lowers them to the
recorded prior assignment. A workspace admin revoke that can't bind its workspace fails saying
P0 can't reach it, and never counts as done: a workspace that answers wrongly may still hold
the role. If the workspace was deleted, the user's admin role went with it. A failed grant's
rollback fails too, with the binding's own error, because the framework's validation hook binds
before the policies show the call is a revoke.

## Unverified facts

INT-32 checks these in a test account:

- The federated account-level token is accepted on workspace APIs (`SCIM /Me`, Unity
  Catalog).
- The error codes Unity Catalog returns for a dropped securable (`CATALOG_`, `SCHEMA_`,
  `TABLE_`, `VOLUME_` and `FUNCTION_DOES_NOT_EXIST`) and for a principal without `MANAGE`
  (a 403).
- The SCIM `remove` path `roles[value eq "account_admin"]`.

INT-303 checks these, for the narrowed permissions:

- `current-metastore-assignment` answers a principal with only a `USER` assignment, with
  `workspace_id` and `metastore_id`, and answers a workspace with no metastore with a 404
  carrying `METASTORE_DOES_NOT_EXIST`.
- A workspace admin's `SCIM /Me` lists the `admins` group by its `display` name.
- The Unity Catalog permissions `PATCH` answers an email no principal has with a 400 or 404
  carrying `PRINCIPAL_DOES_NOT_EXIST`, on an `add` and on a `remove`. Whether a permissions
  `GET` filtered to that email fails the same way or returns nothing.
- Whether Databricks matches the `principal` email ignoring case, so a P0 email that differs
  in case from the Databricks username still names that user.
- The workspace-level permission assignment API, a `preview` path missing from the API
  reference: `GET /api/2.0/preview/permissionassignments` answers in the account API's shape,
  `PUT .../principals/<id>` with `{"permissions":["ADMIN"]}` or `["USER"]` sets the
  assignment, `PUT ["USER"]` cleanly demotes an admin, and `DELETE` removes it, all for a
  workspace admin.
- The workspace's proxy of account SCIM (`/api/2.0/account/scim/v2/Users`) answers a
  workspace admin with account SCIM IDs, the same IDs the assignment API takes.
- A workspace's `SCIM /Me` reports the connector's service principal under its account SCIM
  ID, which the own-principal refusal compares against.
- Whether a group whose name is an email in an allowed domain gets the grant. The user ID
  parser refuses anything that isn't an email, but can't tell such a group from a user.

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
  --build-arg WORKSPACE=@p0security/p0-connector-databricks \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-databricks:dev .
```

This will set your locally-built images to have the tag `dev`.

`./build-images.sh 6` builds the same image, tagged `latest`.

## Tests

The tests run from the repository root, as CI runs them. Run `yarn :show-lockfile` and
`yarn install` first (see the root README's lockfile section). Build the monorepo before
testing, because the connector imports the built `@p0security/connector` package:

```bash
yarn :build
yarn :test services/p0-connector-databricks
yarn workspace @p0security/p0-connector-databricks typecheck
```

The tests stub Databricks and AWS STS (`src/__tests__/http.ts` and `src/__tests__/sts.ts`), so
they never call either.

## Trying a change in a dev install

P0 always invokes the deployed Lambda, so to try a change, deploy an image built from your
branch to the connector of a dev install. The app's
`packages/integrations/databricks/README.md` describes the dev accounts and how to install the
integration in a dev tenant.

The connector's Terraform creates the ECR repository with immutable tags, so each push needs a
tag of its own. Build the image as above, then push it and point the Lambda at it:

```bash
AWS_ACCOUNT_ID="your-aws-account-id"
AWS_REGION="your-aws-region"
REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/p0-connector-databricks"
TAG="dev-$(date +%s)"

aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "${REPO%%/*}"

docker tag p0-connector-databricks:dev "$REPO:$TAG"
docker push "$REPO:$TAG"

aws lambda update-function-code --region "$AWS_REGION" \
  --function-name p0-connector-databricks --image-uri "$REPO:$TAG"
```

The next `terraform apply` of the connector puts the pinned image back. Its logs are in
CloudWatch, in `/aws/lambda/p0-connector-databricks`.

## Releasing

A pull request builds the image but doesn't push it. Each merge to `main` pushes it to Docker
Hub as `p0security/p0-connector-databricks:sha-<short commit>`
(`.github/workflows/docker.yaml`). New installs get the image that `CONNECTOR_IMAGE` in the
app's `packages/integrations/databricks/frontend/src/iac.ts` names, so a release only reaches
customers once the app bumps it. The app's README describes the bump, including the
`connector_image_tag` in terraform-provider-p0's `p0_databricks_connector` example. If the
change alters the connector's API, the same app PR bumps `submodules/security-perimeter`.
