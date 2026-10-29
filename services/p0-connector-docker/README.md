# p0-connector-docker

Docker Hub connector: gives a person a role in a Docker Hub organization, just
in time, and takes it back when the grant ends.

Ships as both an AWS Lambda container image and a GCP Cloud Run container
image, built from the same workspace with two different Dockerfiles.

## What it does

One resource-root access, `role`. The user is the requestor's P0 email, which
is both the user body and the user id. Nothing the requestor types is an
identity. The policy is `{ role }`: `member`, `editor` or `owner` to grant, or
`null` to take back what P0 gave.

The request context carries the org, a pointer to its organization access
token (`tokenSecret`), and two things P0 knows about the request:

- `standingMember`: the Docker username, account uuid and role P0 recorded
  after approval for someone who was already in the org, or `null` for someone
  P0 invites.
- `grantCompleted`: whether P0 finished granting the request.

### A standing member

- **Grant:** looks the username up, then sets the requested role with
  `PUT /v2/orgs/{org}/members/{username}`. It refuses unless the live account
  still has the recorded uuid and its Docker email is the requestor's email:
  "Your Docker account changed after you requested access. Request access
  again." P0 sends both an email and a username, and this tie is what stops an
  allowed email being paired with someone else's username.
- **Revoke:** puts the recorded role back, whatever the role is now. If the
  account has left the org, or the username names another account, nothing
  changes and the revoke succeeds. A standing member is never removed.

  Lowering a role is never blocked. If an admin lowered the role during the
  grant, putting the recorded role back would raise it, so that has to pass
  the same checks as a grant. When it doesn't, the member keeps the lower role
  and the revoke still succeeds.

### Someone P0 invites

- **Grant:** invites them at their P0 email with the requested role, with
  `POST /v2/invites/bulk`. The grant is done once Docker Hub accepts the
  invite. This path only ever invites, and never sets a role:
  - If a member already has the email, they joined between approval and the
    grant. The grant is refused ("You joined <org> after you requested
    access. Request access again.") and they request again as a member.
  - A pending invite that already gives the requested role is left alone. One
    that gives another role is refused: "You have a pending invite to <org>.
    Accept it, or ask an owner of <org> to cancel it. Then request again."
  - If Docker Hub answers that they're already a member, their account is in
    the org under another email. The grant is refused, and says so.
  - When Docker Hub refuses the invite, because the org has no seats left for
    example, the grant fails with Docker Hub's reason.
- **Revoke:** puts the org back as it was before the grant, in one run. It
  cancels every pending invite to their email, then, if `grantCompleted` is
  true, removes the member with that email, whether or not it cancelled an
  invite. When the grant never completed it only cancels invites: after a
  failed grant, whoever holds the email joined some other way. The connector
  finds them by email alone, because nothing created at grant time, such as
  the invite's id, can be stored.

### What holds

- **Only `setPoliciesForUser` changes anything in Docker Hub.** `getUser`
  returns the email without calling Docker Hub, and never `null`, so
  `createUser` is never reached. `deleteUser` is a deliberate no-op.
- **Every call can run twice.** A second grant finds the invite the first one
  sent. A second revoke finds nothing left to take back.
- **P0 can't raise anyone whose Docker email is outside the allowed domains.**
  `DOMAIN_ALLOW_PATTERN` gates a grant, both `list` lookups, and a revoke's
  restore when it would raise a role. A refusal reads "Your email domain isn't
  allowed for Docker Hub organization <org>. Ask your P0 admin to check the
  connector's allowed domains."
- **A revoke isn't gated by the allowed domains.** It can lower a role, cancel
  an invite, or remove someone P0 invited, so tightening the pattern can't
  strand access granted earlier.
- **Two members with the same email fail the call,** a revoke included, so a
  person can sort out which is which.
- **A refusal the requestor reads means nothing was written.** Each
  `validation_error` is thrown before the connector changes anything. When
  Docker Hub refuses a cancel or the removal after the connector has
  cancelled an invite, the error is a `dependency_violation` instead.
- **P0 never holds the token.** See
  [The organization access token](#the-organization-access-token).

### Lookups

`list` gets no request context, so each query is
`{ type, context: { org, tokenSecret }, email }`. Neither is a listing: each
returns `[]` or what it found for that one email.

- `member`: the org member with the email, as
  `{ key: <username>, value: <uuid>, group: <role> }`. A core role is
  lower-case. A custom role is reported by its name, which is how P0
  recognises a custom-role holder and refuses their request: the connector
  can't rank a custom role, and only ever sets a core one.
- `invite`: a pending invite to the email, as
  `{ key: <invite id>, value: <role> }`.

### Install validation

`install.validation.get` reports three checks separately, and the
allowed-domain pattern as deployed:

- `tokenAccepted`: Docker Hub exchanged the token for a JWT.
- `canReadMembers`: it could read the org's member list.
- `canInvite`: Docker Hub accepted a dry-run invite, which sends nothing and
  uses no seat. The invite is for `p0-install-check@example.com`, an address
  no one can hold, and doesn't go through the allowed-domain check.

Only a 401 or a 403 reports a check as `false`: that's what a token without
the scope looks like. Any 2xx passes `canInvite`, because the status Docker
Hub gives the invitee is about the address or the org's seats, not the token.
A 400 or a 409 fails the call with Docker Hub's reason, and a rate limit, a
server error or no answer fails it so that P0 tries again.

### Errors

| Docker Hub                                                                     | Connector error                                  |
| ------------------------------------------------------------------------------ | ------------------------------------------------ |
| Token exchange refused (400, 401 or 403)                                       | `insufficient_privileges`                        |
| Any other 401 or 403                                                           | `insufficient_privileges`                        |
| The token secret is missing, or can't be read                                  | `object_not_found`, `insufficient_privileges`    |
| 404 on the member or the invite, during a revoke                               | Already gone, so not an error                    |
| 404 anywhere else                                                              | `object_not_found`                               |
| 429                                                                            | `rate_limited`                                   |
| 5xx, or no answer, also while the body arrives                                 | `upstream_unavailable`                           |
| 400, 409, or an invite Docker Hub refuses                                      | `validation_error`, with Docker Hub's reason     |
| 400 or 409 on a cancel or the removal, after the connector cancelled an invite | `dependency_violation`, with Docker Hub's reason |

## The organization access token

The connector acts as an
[organization access token](https://docs.docker.com/security/access-tokens/organization-access-tokens/)
that an owner of the org creates, with two organization scopes: **Member
Edit** and **Invite Edit**. It needs no repository scopes.

The token lives in the customer's own secret manager, AWS Secrets Manager or
Google Secret Manager, as the secret's whole value. Each call from P0 carries
a pointer to the secret, never the token. The connector reads the secret with
its own cloud identity on every call, and exchanges the token at
`POST /v2/auth/token` for a JWT only when it has none for that org, pointer
and secret version. It keeps the JWT in memory until a minute before the
JWT's own expiry. Calls that arrive together share one exchange. If Docker
Hub answers a cached JWT with a 401, the connector drops it, exchanges the
token again and retries the call once. The token, the JWT and the
`Authorization` header never go into a log line or an error.

To rotate the token, store the new one as a new version of the same secret.
It takes effect on the next call, and so does pulling the connector's grant
to read the secret.

P0 sends the secret's name with each call, so any other secret the connector's
identity can read is one a request could point it at. Grant it the token
secrets of the orgs it serves and nothing else: never a wildcard that could
match another secret, and never a grant at the account or project level.

### AWS Secrets Manager

The Lambda's execution role needs `secretsmanager:GetSecretValue` on each
secret's full ARN. If a secret is encrypted with a customer-managed KMS key,
the role also needs `kms:Decrypt` on that key.

### Google Secret Manager

The Cloud Run service account needs two roles, both bound on the secret:
`roles/secretmanager.secretAccessor` and `roles/secretmanager.viewer`.

The accessor role isn't enough on its own. The shared secret client
(`@p0security/connector-secret-manager-client`) reads the latest version's value, then
reads that version's metadata, and the second call needs
`secretmanager.versions.get`, which the accessor role doesn't have. Without
it the read is refused, and the connector reports that it isn't allowed to
read the secret.

## Known gaps

Accepted for the beta:

- A standing member whose Docker account uses a personal email isn't matched,
  so they're invited at their work email instead. Keep Docker emails equal to
  work emails.
- If someone accepts an invite with an account on a different email, or
  changes their Docker email after joining, the revoke finds nobody by email.
  It reports the access as already gone while the account stays in the org.
- Custom roles can't be requested, and someone who holds one can't request at
  all. Restoring a custom role by name was never tried against Docker Hub.
- Whether the member list can show an email its owner hasn't verified isn't
  known. If it can, someone could put a colleague's address on their Docker
  account and receive that colleague's grant.
- A revoke cancels every pending invite to the email, including one an admin
  sent by hand in the meantime.
- If a grant fails after Docker Hub may have sent the invite, and the person
  accepts it before P0 rolls the grant back, they stay in the org: a request
  that never finished granting never removes a member.
- There's no background health check. An expired or revoked token shows up as
  an install problem on the next request or install check.
- Accepting an invite and removing a member were not exercised against Docker
  Hub when the API was verified.

## Configuration

The connector reads its configuration from environment variables, which the
customer's Terraform sets on the deployment.

| Variable               | What it is                                                                                                                                     | Required       |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| `DOMAIN_ALLOW_PATTERN` | A regular expression for the email domains the connector acts for. The connector refuses to start when it's missing, blank or doesn't compile. | Yes            |
| `INVOKER_SA_EMAIL`     | The service account allowed to call the connector.                                                                                             | Cloud Run only |
| `LOG_LEVEL`            | The pino log level. Defaults to `info`.                                                                                                        | No             |

`DOMAIN_ALLOW_PATTERN` runs as written against the part of an email after the
`@`, apart from whitespace around it, which is dropped. Nothing anchors it for
you. `acme\.com` also matches `notacme.com`, so
write `^acme\.com$`. One pattern covers every organization the connector
serves.

The image build sets `GIT_REF`, `BUILD_DATE` and `WORKSPACE`, which the
connector reports as its metadata.

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
  --build-arg WORKSPACE=@p0security/p0-connector-docker \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-docker:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-docker \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-docker-gcloud:dev .
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

docker tag p0-connector-docker:dev \
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
helper entry.

Tag the locally-built image with the correct destination.

```bash
gcloud auth configure-docker "$GCP_REGION-docker.pkg.dev"

docker tag p0-connector-docker-gcloud:dev \
  "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-docker-gcloud:dev"

docker push "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-docker-gcloud:dev"
```

## Deploying a new connector image

If you already have a Lambda function set up, go to the AWS Console and deploy
the function from the newly pushed image.

If you already have a Cloud Run service set up instead, go to the GCP Cloud
Console and deploy a new revision from the newly pushed image.

Either way, the deployment must set `DOMAIN_ALLOW_PATTERN`, or the new image
won't start.
