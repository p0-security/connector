# p0-connector-auth0

Auth0 connector: gives a person access inside an Auth0 tenant, just in time,
on their own Auth0 user, and takes it back when the grant ends.

Ships as both an AWS Lambda container image and a GCP Cloud Run container
image, built from the same workspace with two different Dockerfiles.

## What it does

The connector acts for P0 on one or more Auth0 tenants, each through the
tenant's Management API, as a machine-to-machine application the customer
creates.

### Install validation

`install.validation.get` runs four checks in order, and fails at the first
one that doesn't pass, naming it in the error's `payload.step`:

1. `secret`: the connector can read the client secret.
2. `authenticate`: the tenant exchanges the client id and secret for a
   Management API token.
3. `scopes`: the token carries every scope in
   [the scopes](#the-management-api-application). A missing scope fails the
   check, which lists every one that's missing. Extra scopes are ignored.
4. `domains`: the connector has a usable `DOMAIN_ALLOW_PATTERN`.

Once they all pass it returns the tenant and the pattern as deployed.

### The user

The framework's user is the requestor's P0 email, and `getUser` returns it
without asking Auth0. P0 never creates or deletes Auth0 users, and
`deleteUser` is a deliberate no-op. The Auth0 user P0 found for the email
arrives in the request context as `auth0UserId`. A grant is refused unless
the email is in the allowed domains and that user still has it. A revoke
takes back from that user whatever its email is now.

Each access's `setPoliciesForUser` gets exactly one policy, and touches only
its own access's grant.

### `role`

A tenant role, assigned to the user directly. The policy is `{ roleId }` to
grant, or `null` to revoke the request context's `roleId`.

- **Grant:** `POST /users/{id}/roles` with the one role. A 409, or a 400
  that says the role is already assigned, counts as granted once reading the
  user's roles back confirms it: Auth0 answers 409 for more than that. P0
  refuses a request for a role the user holds, so one already assigned is
  P0's own, from a rerun step.
- **Revoke:** `DELETE /users/{id}/roles` with the one role. A 404, for a user
  or role that's gone, counts as revoked. Any other role stays.

### `permission`

A permission on an API, assigned to the user directly. The policy is
`{ resourceServerIdentifier, permissionName }` to grant, or `null` to revoke
the request context's pair. The pair is the key in both.

- **Grant:** `POST /users/{id}/permissions` with the one permission. "Already
  there" counts as done once the user's direct permissions confirm it.
- **Revoke:** `DELETE /users/{id}/permissions` with the one permission. A
  404 counts as revoked.

Only the direct assignment is touched. A permission the user also holds
through a role stays when the grant ends, and P0 decides whether a permission
is already held from direct assignments alone
(`GET /users/{id}/effective-permissions`). That the `DELETE` leaves a role's
permission alone is inferred from Auth0's docs, not yet seen on a tenant.

### `organization`

Membership of an Auth0 organization, optionally with a tenant role in it. The
policy is `{ organizationId, roleId? }` to grant, or `null` to revoke. P0
records at stage whether the user was already a member (`wasMember`) and the
member's roles in the organization (`priorRoleIds`), and sends both in the
request context: the connector can't keep what it learns during a grant.

| Member at stage | Role requested | Grant                         | Revoke                           |
| --------------- | -------------- | ----------------------------- | -------------------------------- |
| no              | no             | add the membership            | remove the membership            |
| no              | yes            | add the membership, then role | remove the role, then membership |
| yes             | yes, not held  | add the role                  | remove only that role            |
| yes             | held, or none  | refused by P0                 |                                  |

- If the role fails after the connector added the membership, it removes the
  membership again and fails with `dependency_violation`, saying whether the
  removal worked.
- A revoke is one idempotent pass, and a 404 counts as gone. It never removes
  a membership that was there at stage, or a role the member held then. The
  role goes before the membership, because whether removing a member drops
  their roles in the organization isn't documented.
- If Auth0 refuses the membership's removal (a 400 or 409) after the revoke
  removed the role, it fails with `dependency_violation` and Auth0's reason.
  A rate limit or an outage keeps its own error type, so P0 retries it.
- "Already there" on a grant counts as done once a read confirms it, as with
  `role`. A member at Auth0's cap of 50 roles gets a 409 too.

Organization-scoped roles are in Early Access and aren't supported.

### Lookups

`list` gets no request context, so each query carries the tenant
credentials. Every access answers the same queries.

- `users`: the Auth0 users with the requestor's email, one per unlinked
  identity, as `{ key: <user id>, value: <connection>, group: <email> }`.
  Auth0's lookup is case-sensitive, so the connector looks the email up as
  given and lower-cased, and merges the two.
- `roles`, `apis`, `organizations`: the tenant's roles, APIs and
  organizations, as `{ key: <id>, value: <name> }`. An API's key is its
  identifier.
- `permissions`: the permissions one API defines, as
  `{ key: <permission>, value: <description> }`.
- `user-roles`: the roles assigned to the user directly.
- `user-permissions`: the permissions assigned to the user directly on one
  API (`resourceServerIdentifier`), as
  `{ key: <permission>, value: <permission>, group: <API identifier> }`. One a
  role gives is left out, even when the user also holds it through a role.
- `org-membership`: `[]` when the user isn't a member of the organization,
  or else `{ key: "member", value: <user id> }` followed by each of the
  member's roles in it, with `group: "role"`.

The queries about a user carry the requestor's email and the Auth0 user id
P0 found for it. They're refused for an email outside the allowed domains,
and when the user no longer has the email. The tenant-wide listings aren't
about anyone, and aren't gated.

### What holds

- **The tenant is the canonical Auth0 domain,** `<name>[.<region>].auth0.com`.
  The Management API's audience is always that domain, so a custom domain is
  refused. The connector checks it again before it becomes a URL's host.
- **P0 never holds the client secret.** See
  [The Management API application](#the-management-api-application).
- **A rate limit is retried.** Free and developer tenants allow about 10
  requests a second. After a 429 the connector waits 10 seconds and tries
  again, up to three times. Then the 429 goes back to P0 as `rate_limited`,
  with `retryAfter` from `Retry-After`, or else from `x-ratelimit-reset`.

### Errors

| Auth0                                          | Connector error                               |
| ---------------------------------------------- | --------------------------------------------- |
| Client credentials refused (400, 401 or 403)   | `insufficient_privileges`                     |
| Any other 401 or 403                           | `insufficient_privileges`                     |
| The client secret is missing, or can't be read | `object_not_found`, `insufficient_privileges` |
| 404                                            | `object_not_found`                            |
| 429                                            | `rate_limited`, with `retryAfter`             |
| 5xx, or no answer, also while the body arrives | `upstream_unavailable`                        |
| 400 or 409                                     | `validation_error`, with Auth0's reason       |

## The Management API application

The connector acts as a machine-to-machine application in the tenant,
authorized for the Auth0 Management API with these scopes:

- `read:users`, `update:users`
- `read:roles`, `read:role_members`, `create:role_members`,
  `delete:role_members`
- `read:resource_servers`, `read:user_effective_permissions`
- `read:organizations`, `read:organization_members`,
  `read:organization_member_roles`, `create:organization_members`,
  `delete:organization_members`, `create:organization_member_roles`,
  `delete:organization_member_roles`

The application's client id is part of the P0 install. Its client secret
lives in the customer's own secret manager, AWS Secrets Manager or Google
Secret Manager, as the secret's whole value. Each call from P0 carries the
client id and a pointer to the secret, never the secret. The connector reads
the secret with its own cloud identity on every call, and exchanges it at
`POST https://{tenant}/oauth/token` for a token only when it has none for that
tenant, client, pointer and secret version. It keeps the token in memory until
five minutes before the token's own expiry. Calls that arrive together share
one exchange. If the tenant answers a cached token with a 401, the connector
drops it, exchanges again and retries the call once. The secret, the token and
the `Authorization` header never go into a log line or an error.

To rotate the secret, store the new one as a new version of the same secret.
It takes effect on the next call, and so does pulling the connector's grant to
read the secret.

P0 sends the secret's name with each call, so any other secret the
connector's identity can read is one a request could point it at. Grant it the
client secrets of the tenants it serves and nothing else: never a wildcard
that could match another secret, and never a grant at the account or project
level.

### AWS Secrets Manager

The Lambda's execution role needs `secretsmanager:GetSecretValue` on each
secret's full ARN. If a secret is encrypted with a customer-managed KMS key,
the role also needs `kms:Decrypt` on that key.

### Google Secret Manager

The Cloud Run service account needs two roles, both bound on the secret:
`roles/secretmanager.secretAccessor` and `roles/secretmanager.viewer`. The
shared secret client reads the latest version's value, then that version's
metadata, and the second call needs `secretmanager.versions.get`, which the
accessor role doesn't have.

## Configuration

The connector reads its configuration from environment variables, which the
customer's Terraform sets on the deployment.

| Variable               | What it is                                                                                                                                     | Required       |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| `CONNECTOR_AUDIENCE`   | The audience P0 mints the ID token for: the service URL the Cloud Run API reports as `uri`.                                                    | Cloud Run only |
| `DOMAIN_ALLOW_PATTERN` | A regular expression for the email domains the connector acts for. The connector refuses to start when it's missing, blank or doesn't compile. | Yes            |
| `INVOKER_SA_EMAIL`     | The service account allowed to call the connector.                                                                                             | Cloud Run only |
| `LOG_LEVEL`            | The pino log level. Defaults to `info`.                                                                                                        | No             |

`DOMAIN_ALLOW_PATTERN` runs as written against the part of an email after the
`@`, apart from whitespace around it, which is dropped. Nothing anchors it for
you. `acme\.com` also matches `notacme.com`, so write `^acme\.com$`. One
pattern covers every tenant the connector serves.

The image build sets `GIT_REF`, `BUILD_DATE` and `WORKSPACE`, which the
connector reports as its metadata.

## Creating local builds

Both images pull P0's base images from a private GCP Artifact Registry, so log
in and register gcloud as a Docker credential helper for that host first. This
is required for the AWS Lambda image too:

```bash
gcloud auth configure-docker us-west1-docker.pkg.dev
```

Then run these from the repository root:

### AWS Lambda

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/lambda/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-auth0 \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-auth0:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-auth0 \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-auth0-gcloud:dev .
```

This will set your locally-built images to have the tag `dev`. To publish and
deploy one, follow the steps in
[the Docker Hub connector's README](../p0-connector-docker/README.md#publishing-local-builds),
with `auth0` in place of `docker`. The deployment must set
`DOMAIN_ALLOW_PATTERN`, or the new image won't start.
