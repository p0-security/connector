# p0-connector-launchdarkly

LaunchDarkly connector: gives a person time-bound access on their existing
LaunchDarkly member, and takes it back when the grant ends.

Ships as both an AWS Lambda container image and a GCP Cloud Run container
image, built from the same workspace with two different Dockerfiles.

One connector serves any number of LaunchDarkly accounts. Each call from P0
names the account's `instance` (`commercial`, `eu` or `federal`), its
`accountId`, and the secret that holds its access token, as `secret`. The
instance picks the host. P0 never sends a URL.

## What it does

The connector runs install validation, answers the lookups, and grants and
revokes one access, `base-role`: an existing member's base role, which
LaunchDarkly's API changes on every plan. It never invites or removes a
member, and calls nothing only Enterprise offers: no custom role, team or
role attribute is read or written.

### Grants and revokes

P0 sends the member's `_id`, the context of one request, and `policies`:
every base role that request and the member's other open requests on the
same account hold.

- A call is a revoke when its context says `operation: revoke`, or when the
  request's own target isn't in `policies`. The call that rolls back a
  failed grant still says `grant`. Every other target in `policies` is
  another request's: a grant writes only its own request's target, and a
  revoke leaves the others in place.
- Before a grant writes anything, it checks the email's domain, before it
  reads the secret. Then it checks that the access token still belongs to
  the account and doesn't act as the member (`own_member`). Last, it checks
  that the member still has the email, has verified it and has joined
  (`member_changed`). After the write, it reads the member back up to three
  times, a second apart, and fails unless the change shows. A read back that
  LaunchDarkly limits (429, waiting its `Retry-After` up to 2 seconds),
  fails with a 5xx or doesn't answer counts as not showing it yet, except
  the last.
- A revoke checks only that the access token still belongs to the account,
  and otherwise fails with `insufficient_privileges`, writing nothing. It
  acts on the ids P0 recorded, and is done when LaunchDarkly no longer has
  the member.
- Running a grant or a revoke again is safe: it changes nothing the first
  run made.

- A grant raises the base role to the request's role, and never lowers it.
- A revoke lowers it to the highest role left in `policies`, or to the role
  the member held before, and never raises it.

Base roles rank `no_access < reader < writer < admin < owner`. The
connector never writes over `owner`, or over a base role it doesn't know.
LaunchDarkly ignores a member's base role while they hold a custom role, so
a grant is refused for a member whose own `customRoles` isn't empty
(`base_role_ignored`). The connector doesn't look the roles up.

A member's JSON Patch carries no comment: LaunchDarkly documents none for
it.

### Lookups

The access's `list` answers two queries, each with the account as its
`context`. `src/accesses/common/definition.ts` has each answer's shape.

- `member { email }`: the one member with the email, ignoring case, who has
  verified it and joined, and isn't the access token's own member. An email
  outside `DOMAIN_ALLOW_PATTERN` finds no one, and LaunchDarkly isn't asked.
- `member-state { memberId }`: the member's base role, and the ids of the
  custom roles in their own `customRoles`.
- Before either looks a member up, it checks that the access token belongs
  to the account, and refuses with `member_changed`
  (`payload.changed: "account"`) when it doesn't.

Members are read 20 rows a page, the default LaunchDarkly documents. Its
spec gives the list no larger maximum. A listing that runs past 1,000 pages
fails. One invocation spends at most 45 seconds calling
LaunchDarkly: a call that would start later fails with
`upstream_unavailable`.

### Install validation

`install.validation.get` takes `{ instance, secret }`, and checks, in this
order, that:

1. `secret`: the connector can read the access token from the secret.
2. `authenticate`: LaunchDarkly accepts the token on
   `GET /api/v2/caller-identity`, and says which account it belongs to. A
   personal token must also say which member it acts as.
3. `domains`: `DOMAIN_ALLOW_PATTERN` is set, and compiles.

Every plan validates the same way: the connector doesn't ask which plan the
account is on.

It returns `accountId`, `tokenKind` (`service` or `personal`),
`tokenOwnerMemberId` (the member a personal token acts as, or `null`), and
`domainPattern`, the pattern less the whitespace around it. Nothing of the
token is reported.

A failed check fails the call. The error's `payload.step` names the check,
and `payload.host` the instance's host.

### Refusals

P0 shows its own message for a refusal: a `validation_error` with a
`payload.reason` from a closed set: `domain_not_allowed`,
`domain_pattern_unusable`, `own_member`, `member_changed` and
`base_role_ignored`.

## Calling LaunchDarkly

- The host is fixed by the instance: `app.launchdarkly.com`,
  `app.eu.launchdarkly.com` or `app.launchdarkly.us`. The base is
  `https://<host>/api/v2`.
- Every call sends `Authorization: <token>`, with no `Bearer`, and
  `LD-API-Version: 20240415`, the API version the connector is written
  against.
- The connector follows no redirect, reads at most 2 MiB of an answer and
  16 KiB of an error, and gives up after 10 seconds. It doesn't send a
  failed call again, except to read a member back after a grant. P0
  decides when to try again.
- It makes only the calls in its allowlist, by route: three reads
  (`GET /caller-identity`, `GET /members`, `GET /members/{id}`) and one
  write (`PATCH /members/{id}`), all of them on every plan. `GET /members`
  only with one `email:` filter. A member's JSON Patch only tests and
  replaces `/role` with a base role below owner. Anything else is refused
  before it is sent.
- Messages and log lines name a call by its route template, never its URL:
  `GET /members?filter=email:` holds an email.

| LaunchDarkly answers         | Error type                |
| ---------------------------- | ------------------------- |
| 401, 403                     | `insufficient_privileges` |
| 404                          | `object_not_found`        |
| 400, 405, 409, 422           | `validation_error`        |
| 429                          | `rate_limited`            |
| 5xx, or no answer            | `upstream_unavailable`    |
| a redirect, any other status | `validation_error`        |
| a 2xx it wouldn't send       | `unknown`                 |

A 429 carries `payload.retryAfter`, in seconds, from `Retry-After`,
`X-Ratelimit-Reset` or `X-Ratelimit-Auth-Token-Reset`. A refused write quotes
LaunchDarkly's own message, cut short. A refused read doesn't, since it can
echo what was asked.

## The access token

The token is an Admin's personal access token. It lives in the customer's
AWS Secrets Manager or Google Secret Manager, matching the cloud the
connector runs on, as the secret's whole value: the token itself, with
nothing around it.
Whitespace around it is dropped. The connector reads it on every call, so a
rotated token applies from the next one. P0 holds a pointer to the secret
only.

On AWS the connector's identity needs `secretsmanager:GetSecretValue` on the
secret, and `kms:Decrypt` on its key if it uses a customer-managed key. On
Google Cloud it needs `roles/secretmanager.secretAccessor` and
`roles/secretmanager.viewer` on the secret.

## The domain allowlist

The connector only looks up, or gives access to, an email whose domain
`DOMAIN_ALLOW_PATTERN` allows. P0 never sends the pattern, so nothing in a
call can widen it.

- The pattern is matched against the whole domain, the text after the `@`,
  ignoring case. Write it without anchors, and escape the dots:
  `p0\.dev|p0security\.com`.
- A subdomain is allowed only when the pattern says so, as
  `([a-z0-9-]+\.)*p0\.dev` does.
- While the pattern is unset, blank or doesn't compile, every email is
  refused and install validation fails.
- It is read on every call. Removing access never consults it.

## Configuration

| Variable               | What it is                                                                                                                                      | Required       |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| `DOMAIN_ALLOW_PATTERN` | A regular expression for the email domains that may receive access. See [the domain allowlist](#the-domain-allowlist).                          | Yes            |
| `INVOKER_SA_EMAIL`     | The service account allowed to call the connector, which is P0's. Without it the Cloud Run service answers every call but `/health` with a 403. | Cloud Run only |
| `LOG_LEVEL`            | The pino log level. Defaults to `info`.                                                                                                         | No             |

The Cloud Run service listens on `PORT`, 8080 when unset. The image build
sets `GIT_REF`, `BUILD_DATE` and `WORKSPACE`, which the connector reports as
its metadata.

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
  --build-arg WORKSPACE=@p0security/p0-connector-launchdarkly \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-launchdarkly:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-launchdarkly \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-launchdarkly-gcloud:dev .
```

This will set your locally-built images to have the tag `dev`.
