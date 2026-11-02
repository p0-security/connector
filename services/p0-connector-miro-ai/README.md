# p0-connector-miro-ai

Miro (AI) connector: gives a requester's own Miro user time-bound access to
one Miro board, so the agent signed in to Miro's MCP as them can reach it,
and takes it back when the grant ends.

Ships as both an AWS Lambda container image and a GCP Cloud Run container
image, built from the same workspace with two different Dockerfiles.

One connector serves any number of Miro teams. Each call from P0 names the
team's `teamId` and the secret that holds the connector user's access
token, as `secret`. The connector calls `api.miro.com` only.

## What it does

So far the connector runs install validation and reports its metadata. The
`board` access, with its grant, revoke and board listing, comes in INT-1110.

### Install validation

`install.validation.get` takes `{ secret }`, and checks, in this order,
that:

1. `secret`: the connector can read the access token from the secret.
2. `authenticate`: Miro accepts the token on `GET /v1/oauth-token`, says
   which team it was installed into, and lists the scopes `boards:read`,
   `boards:write` and `team:read`. A token keeps the scopes it was issued
   with, so a missing one fails with "Add the scope to the app, then
   reinstall it and store the new token", and `payload.missingScopes`.
3. `boards`: counts the team's boards whose `currentUserMembership.role` is
   `owner` or `coowner`, from `GET /v2/boards?team_id=...`, 50 to a page.
   A board the connector user reaches only through team access doesn't
   count. Zero passes, and P0 shows it as a warning.

It returns `teamId` and `shareableBoards`. Every check only reads. Nothing
of the token is reported.

A failed check fails the call. The error's `payload.step` names the check.

### Refusals

P0 shows its own message for a refusal: a `validation_error` with a
`payload.reason` from a closed set: `not_in_team`, `pending_invite`,
`member_changed` and `board_not_shareable`. The board access raises them.

## Calling Miro

- Every call goes to `https://api.miro.com` and sends
  `Authorization: Bearer <token>`.
- The connector follows no redirect, reads at most 2 MiB of an answer,
  drops an error's body unread, and gives up after 10 seconds.
- On a 429 it waits `Retry-After`, at most 2 seconds, or 1 and then 2
  seconds when Miro says nothing, and tries again, 3 tries in all. It
  doesn't send any other failed call again: P0 decides when to try again.
- It makes only the calls in its allowlist, by route: `GET /v1/oauth-token`
  and `GET /v2/boards`. Anything else is refused before it is sent.
- Miro sends some ids as JSON numbers above 2^53, which `JSON.parse` alone
  rounds to another id. The connector reads every Miro id as a string.
- Messages and log lines name a call by its route template, never its URL,
  and never quote Miro's own message, which can echo the request.

| Miro answers                 | Error type                |
| ---------------------------- | ------------------------- |
| 401, 403                     | `insufficient_privileges` |
| 404                          | `object_not_found`        |
| 400, 405, 409, 422           | `validation_error`        |
| 429, after the retries       | `rate_limited`            |
| 5xx, or no answer            | `upstream_unavailable`    |
| a redirect, any other status | `validation_error`        |
| a 2xx it wouldn't send       | `unknown`                 |

A 429 carries `payload.retryAfter`, in seconds, from `Retry-After`.

## The access token

The token belongs to a dedicated connector user, from a private Miro app
with the `boards:read`, `boards:write` and `team:read` scopes and
non-expiring tokens ("Install app and get OAuth token"). It lives in the
customer's AWS Secrets Manager or Google Secret Manager, matching the cloud
the connector runs on, as the secret's whole value: the token itself, with
nothing around it. Whitespace around it is dropped. The connector reads it
on every call, so a rotated token applies from the next one. P0 holds a
pointer to the secret only.

On AWS the connector's identity needs `secretsmanager:GetSecretValue` on the
secret, and `kms:Decrypt` on its key if it uses a customer-managed key. On
Google Cloud it needs `roles/secretmanager.secretAccessor` and
`roles/secretmanager.viewer` on the secret.

## Configuration

| Variable           | What it is                                                                                                           | Required       |
| ------------------ | -------------------------------------------------------------------------------------------------------------------- | -------------- |
| `INVOKER_SA_EMAIL` | The service account allowed to call the connector, which is P0's. Without it the Cloud Run service refuses to start. | Cloud Run only |
| `LOG_LEVEL`        | The pino log level. Defaults to `info`.                                                                              | No             |

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
  --build-arg WORKSPACE=@p0security/p0-connector-miro-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-miro-ai:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-miro-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-miro-ai-gcloud:dev .
```

This will set your locally-built images to have the tag `dev`.
