# p0-connector-argocd

Argo CD connector: gives a person an Argo CD role, just in time, and takes it
back when the grant ends. It does that by writing lines to a P0-owned
`policy.p0.csv` key in `argocd-rbac-cm`, through Argo CD's own API. It never
calls the Kubernetes API.

Ships as both an AWS Lambda container image and a GCP Cloud Run container
image, built from the same workspace with two different Dockerfiles.

## What it does

It answers `argocd.metadata.get`, the `globalRole` and `projectRole`
accesses, and install validation, `argocd.install.validation.get`.

- `src/instance.ts`: the instance P0 sends with each call, `{ url,
managingApp, namespace, secret }`.
- `src/secrets.ts`: `readApiToken(pointer, logger)`, which reads the
  connector's API token from the customer's secret manager.
- `src/argocd/`: the Argo CD API client and the policy model (below).
- `src/accesses/`: the accesses (below).
- `src/install/`: install validation (below).
- `src/allowlist.ts`, `src/refusals.ts` and `src/self-check.ts`: the domain
  allowlist, the reasons a refusal carries, and the privilege self-check.

`./connector` serves the router's type, `ArgoCdConnectorRouter`, each
access's parsers, the instance schema, `argoCdInstance`, install
validation's answer and steps, and the refusal reasons, without loading the handler, the router or the secret manager
client. P0's control plane builds its typed client from it.

## The accesses

Each access is a resource root, as Harbor's is. The user is the grantee's
SSO email, which Argo CD knows them by: `getUser` answers it without a call,
`createUser` refuses, and `deleteUser` does nothing. `setPoliciesForUser`
takes one policy: a role is a grant, and `null` is a revoke of the role the
request context names.

| Access        | Line it writes                      |
| ------------- | ----------------------------------- |
| `globalRole`  | `g, <email>, role:<name>`           |
| `projectRole` | `g, <email>, proj:<project>:<role>` |

A grant runs, in order:

1. the domain allowlist, before the secret is read or Argo CD is called;
2. the line's own refusals: the connector's role, and a user that isn't an
   email P0 writes;
3. `userInfo`, which fails on a token Argo CD answers as anonymous, then the
   privilege self-check;
4. one read of `argocd-rbac-cm` and the AppProjects;
5. the role has to exist: a global role in a key other than `policy.p0.csv`,
   and not `policy.default`'s; a project role on a project the account can
   see that defines it;
6. P0's own line there already is success, with no write: a retried grant;
7. a line Argo CD refuses anywhere refuses the grant, since Argo CD would
   keep enforcing the policy it had;
8. the role held any other way refuses it;
9. a merge patch carrying `policy.p0.csv` alone, then a read that has to
   show the line.

A revoke removes P0's exact line and nothing else, after `userInfo`. A line
that isn't there is success. It checks neither the allowlist nor the
account's privileges: taking access away mustn't depend on either.

Read, change, write isn't atomic, and the patch isn't conditional on the
ConfigMap's `resourceVersion`. P0's lock on the instance, taken around every
call that writes, is what keeps two writes apart.

`list` takes, for `globalRole`:

| Query  | Answers                                                                 |
| ------ | ----------------------------------------------------------------------- |
| `role` | The instance's global roles, or with `role`, that one role or `[]`.     |
| `held` | `[]`, or the role when the user with `email` holds it already, any way. |

and for `projectRole`:

| Query     | Answers                                                                                 |
| --------- | --------------------------------------------------------------------------------------- |
| `project` | The AppProjects the account can see, or with `project`, that one or `[]`.               |
| `role`    | The roles `project` defines, or with `role`, that one role or `[]`.                     |
| `held`    | `[]`, or the role when the user with `email` holds `project`'s `role` already, any way. |

`projectRole` rests on an undocumented Argo CD behaviour: that a global
`g, <email>, proj:<project>:<role>` line grants the project's role. If live
testing disproves it, the access is removed.

### Refusals

A refusal P0 words in its own copy is a `validation_error` whose
`payload.reason` is one of `ARGOCD_REFUSAL_REASONS`: `connector_role`,
`default_role`, `not_an_email`, `domain_not_allowed`,
`domain_pattern_unusable`, `role_not_found`, `project_not_found`,
`self_check_failed`, `already_held` and `policy_not_loaded`.
`src/refusals.ts` says what each means.

### The privilege self-check

Before every grant the connector asks Argo CD's `can-i`, as itself, about
`applications, sync, */*`, `applications, delete, */*`,
`projects, update, *`, `accounts, update, *` and `clusters, update, *`. A
`yes` to any refuses the grant with `self_check_failed`, naming what the
account may do.

## Install validation

`argocd.install.validation.get` takes the instance and runs these checks in
this order. The first that fails is thrown as a `ConnectorError` whose
`payload.step` names it and whose `payload.host` is the instance's host.
P0 reads `step`, so the set and the order are a contract:
`ARGOCD_INSTALL_STEPS` in `src/install/definition.ts`.

| `step`            | Check                                                                                                                                                                              |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pattern`         | `ALLOWED_EMAIL_DOMAIN_PATTERN` is set and compiles. Before any call leaves the connector.                                                                                          |
| `secret`          | The API token's secret reads, and the token can go in a header.                                                                                                                    |
| `reachable`       | `GET /api/version` answers as Argo CD does. (A non-`https` URL is refused before the handler, by the instance's parser.)                                                           |
| `version`         | That version is 3.0.0 or later.                                                                                                                                                    |
| `account`         | `userInfo` is the `p0-connector` local account. Before any `can-i` or project call, which would answer an anonymous caller.                                                        |
| `managing_app`    | The account can read the managing Application, and it is in the project the instance names.                                                                                        |
| `rbac_config_map` | `argocd-rbac-cm` reads through that Application. When the Application doesn't manage it, the install isn't supported.                                                              |
| `scopes`          | `scopes` has `email`. A value that isn't a flow list on one line fails too.                                                                                                        |
| `p0_policy`       | `policy.p0.csv` is absent, or holds only lines P0 writes, spelled as it writes them, with space around a line trimmed as Argo CD trims it. Named by line number, never by content. |
| `policy_loaded`   | Argo CD refuses no line in any policy key. Named by key and line number, never by content.                                                                                         |
| `projects`        | The AppProject list reads.                                                                                                                                                         |
| `self_check`      | The privilege self-check passes. Before the patch, so an account that may do more than it needs never writes.                                                                      |
| `patch`           | An empty merge patch, `{"data":{}}`, of `argocd-rbac-cm` succeeds: the fine-grained `update` permission, which `can-i` can't ask.                                                  |

The empty patch is a real write: argocd-server applies it, it changes
nothing, and it shows in Argo CD's audit log.

When every check passes, it answers `{ argoCdVersion,
allowedEmailDomainPattern }`. No message quotes what Argo CD answered or the
token.

## The Argo CD API client

`src/argocd/client.ts` makes the only calls the connector makes to Argo CD,
as the `p0-connector` account, with `Authorization: Bearer <token>`:

| Method               | Call                                                            |
| -------------------- | --------------------------------------------------------------- |
| `version`            | `GET /api/version`                                              |
| `userInfo`           | `GET /api/v1/session/userinfo`                                  |
| `canI`               | `GET /api/v1/account/can-i/{resource}/{action}/{subresource}`   |
| `getApplication`     | `GET /api/v1/applications/{name}`                               |
| `readRbacConfigMap`  | `GET /api/v1/applications/{name}/resource` for `argocd-rbac-cm` |
| `patchRbacConfigMap` | `POST /api/v1/applications/{name}/resource`, a JSON merge patch |
| `listProjects`       | `GET /api/v1/projects`                                          |

What it holds to:

- It calls the instance's https origin only, follows no redirect, gives
  Argo CD 10 seconds a call, and reads at most 4 MiB of an answer.
- The token is trimmed, and refused before any call unless what is left is
  printable ASCII. It never reaches a log line or an error, and neither does
  a path, a query or anything Argo CD answered.
- A patch writes `policy.p0.csv` and nothing else. Any other key is refused
  before a call is made.
- `userInfo` fails when Argo CD didn't accept the token. Argo CD answers
  that route, and every route when anonymous access is on, as it would an
  anonymous caller, not with a 401. So call `userInfo` before relying on
  `canI` or `listProjects`.
- Argo CD answers 403 for an Application that doesn't exist, as it does for
  one the account may not read. The error says it may be either.

`src/argocd/errors.ts` turns a failed call into the `ConnectorError` P0
shows, and `src/argocd/version.ts` reads `Version` and holds it to 3.0.0 or
later.

## The policy model

`src/argocd/policy.ts` reads `argocd-rbac-cm` as Argo CD does, and builds
the only lines the connector writes. `src/argocd/roles.ts` lists the roles
P0 can offer from what it read.

Reading:

- Policy comes from every `policy*.csv` key: `policy.csv` first, then the
  other `policy.*.csv` keys in order. Each line is trimmed; blank lines and
  lines starting with `#` are skipped; the rest is one CSV record, whose
  fields may be quoted (`"a, b"`, `""` for a quote). As in Argo CD, only the
  space before a field is dropped: `g, alice@example.com , role:x` names
  `alice@example.com ` with the space. A `g` line has three fields and a
  `p` line six.
- Argo CD refuses the whole policy over any other line, and keeps enforcing
  the one it had. `parsePolicy` reports where such lines are
  (`refusedLines`), since what it read is then not what Argo CD enforces.
- `policy.default` is the role every user holds. `scopes` is a YAML flow
  list such as `[groups, email]`; absent or blank, it is `[groups]`.
- `holds(policy, email, grant)` says whether the user already holds exactly
  that role: through a `g` line for their email in any policy key,
  membership of an AppProject role's `groups`, `policy.default`, or a role
  any of those inherits through `g` lines. A broader role doesn't count.
- `holds` can't see a user's IdP groups. A `g` line whose subject is a
  group, and an AppProject role's group, count only when the group is the
  email itself, which is how a user is named when `scopes` has `email`.
- `listRoles` lists `role:readonly`, `role:admin` and every `role:` name a
  `g` or `p` line names, less `role:p0-connector` and the default role; and,
  per AppProject, the names of the roles it defines.

Writing:

- `buildLine(email, grant)` builds `g, <email>, role:<name>` or
  `g, <email>, proj:<project>:<role>` from typed fields. The email is held
  to a plain pattern and lower-cased; a global role is `role:` and printable
  ASCII with no space, `,`, `#` or `"`; a project and a project role are
  held to Argo CD's own name rules; and `role:p0-connector` is refused. A
  refusal is a `PolicyLineError` whose `reason` names the field, never its
  value.
- `addLine` and `removeLine` change `policy.p0.csv`'s value by one such
  line. `removeLine` removes a line only when it is exactly P0's line, but
  for the space Argo CD trims around it, and leaves every other line as it
  was.

## The instance

| Field         | What it is                                                                                                                                                       |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `url`         | The instance's bare `https` origin: no path, no query, and no username or password. Argo CD served under a path (`server.rootpath`) isn't supported.             |
| `managingApp` | The Application that manages `argocd-rbac-cm`, as `<project>/<app>`. Each half is a Kubernetes resource name: lowercase letters, digits, `-` and `.`, up to 253. |
| `namespace`   | The namespace `argocd-rbac-cm` is in, a Kubernetes namespace name. `argocd` when left out.                                                                       |
| `secret`      | A pointer to the secret that holds the API token (below).                                                                                                        |

A refused instance gets fixed messages: no refusal repeats the value it
refused.

## The API token's secret

The connector acts as an Argo CD local account, `p0-connector`, with a
non-expiring API token, one per instance. The token lives in the customer's
own secret manager, AWS Secrets Manager or Google Secret Manager, as JSON:

```json
{ "token": "<api token>" }
```

The connector reads `token` and ignores any other field, so fields can be
added later without a format change. A value that isn't that JSON, or a
blank token, is a `validation_error`.

Each call from P0 carries a pointer to the secret, never the token:

- `{ "manager": "aws", "region": "<region>", "secretId": "<name or ARN>" }`
- `{ "manager": "gcp", "projectId": "<project>", "secretId": "<name>" }`

The connector reads the secret with its own cloud identity on every call, and
keeps nothing between calls. To rotate the token, store the new one as a new
version of the same secret. It takes effect on the next call.

The token never goes into one of the connector's own log lines or errors.
Nothing of the pointer but its manager does either, the secret's id least of
all: on AWS it is any string, so a token pasted where the name goes would
travel with the message. A failure the connector didn't expect is described
by its code or HTTP status, never by its own text.

| What happened                                                               | Error type                |
| --------------------------------------------------------------------------- | ------------------------- |
| The secret doesn't exist, or holds no value yet.                            | `object_not_found`        |
| The secret manager refused the read.                                        | `insufficient_privileges` |
| The secret manager limited the call: AWS's `ThrottlingException`, or a 429. | `rate_limited`            |
| The secret manager couldn't be reached, or answered with a 5xx.             | `upstream_unavailable`    |
| The read failed some other way.                                             | `unknown`                 |
| The value isn't `{"token": "<api token>"}`, or the token is blank.          | `validation_error`        |

A secret manager can refuse a read of a secret that doesn't exist the same
way as one the connector may not read, when the connector's grant covers only
the secrets it should. So a mistyped name may show up as
`insufficient_privileges`, and that message says to check the name too.

P0 sends the secret's name with each call, so any other secret the
connector's identity can read is one a request could point it at. Grant it
the token secrets of the instances it serves and nothing else: never a
wildcard that could match another secret, and never a grant at the account or
project level.

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

| Variable                       | What it is                                                                                                                                                                             | Required       |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| `ALLOWED_EMAIL_DOMAIN_PATTERN` | A regular expression for the email domains that may receive access, matched against the whole domain, ignoring case. Unset, blank or not a regular expression, every grant is refused. | Yes            |
| `CONNECTOR_AUDIENCE`           | The audience P0 mints the ID token for: the service URL the Cloud Run API reports as `uri`. Without it the Cloud Run service refuses to start.                                         | Cloud Run only |
| `INVOKER_SA_EMAIL`             | The service account allowed to call the connector, which is P0's. Without it the Cloud Run service refuses to start.                                                                   | Cloud Run only |
| `LOG_LEVEL`                    | The pino log level. Defaults to `info`.                                                                                                                                                | No             |

On Cloud Run the caller sends a Google ID token as a bearer token, and the
connector accepts it only when its `email` claim is `INVOKER_SA_EMAIL` and
its `aud` claim is exactly `CONNECTOR_AUDIENCE`. `/health` answers without a
token. A Lambda checks no token: IAM decides who may invoke the function.

The Cloud Run service listens on `PORT`, 8080 when unset.

The image build sets `GIT_REF`, `BUILD_DATE` and `WORKSPACE`, which the
connector reports as its metadata.

## Running it locally

Run these from the repository root. Build the workspace and the workspaces it
depends on first:

```bash
yarn workspaces foreach --recursive --topological --from @p0security/p0-connector-argocd run build
```

[`dev/stub-secrets.mjs`](dev/stub-secrets.mjs) is a stand-in for AWS Secrets
Manager on `http://127.0.0.1:4566`, with fake tokens, for the routes that
will read the secret. It isn't in an image. The AWS SDK honours
`AWS_ENDPOINT_URL_SECRETS_MANAGER`, so point the connector at it with that
and any `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. There is no local
stand-in for Google Secret Manager.

[`dev/stub-argocd.mjs`](dev/stub-argocd.mjs) is a stand-in for Argo CD over
https, which answers the client's calls for an install that followed the
steps, with `argocd-token`'s fake token. Its header says how to give it a
certificate.

### GCP Cloud Run

This is the command the Cloud Run image runs. Cloud Run mode always verifies a
Google-signed ID token, so set `INVOKER_SA_EMAIL` and `CONNECTOR_AUDIENCE`,
and send an ID token for that service account with that audience. Any service
account you hold `roles/iam.serviceAccountTokenCreator` on will do. The
[AWS Lambda](#aws-lambda) entry point below takes no token.

```bash
env PORT=18080 INVOKER_SA_EMAIL=<invoker-sa-email> CONNECTOR_AUDIENCE=http://127.0.0.1:18080 \
  yarn workspace @p0security/p0-connector-argocd run p0-connector-argocd
```

Then, from another shell:

```bash
curl -s http://127.0.0.1:18080/health
ID_TOKEN=$(gcloud auth print-identity-token --include-email \
  --impersonate-service-account=<invoker-sa-email> \
  --audiences=http://127.0.0.1:18080)
curl -s -H "Authorization: Bearer $ID_TOKEN" \
  http://127.0.0.1:18080/trpc/argocd.metadata.get
```

### AWS Lambda

The Lambda image runs `handler` from the bundle, which is a plain async
function, so it needs no Lambda runtime. It takes the HTTP request P0 would
have sent.

```bash
yarn workspace @p0security/p0-connector-argocd build-within-docker

node --input-type=module -e '
  const { handler } = await import("./services/p0-connector-argocd/dist/index.mjs");
  console.log(JSON.stringify(await handler({ url: "https://x/trpc/argocd.metadata.get", method: "GET", headers: {} })));
'
```

## Creating local builds

Both images pull P0's base images from a private GCP Artifact Registry, so
log in and register gcloud as a Docker credential helper for that host first.
This is required for the AWS Lambda image too:

```bash
gcloud auth configure-docker us-west1-docker.pkg.dev
```

Then run these from the repository root:

### AWS Lambda

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/lambda/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-argocd \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-argocd:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-argocd \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-argocd-gcloud:dev .
```

CI builds both images on every pull request, as `p0-connector-argocd` and
`p0-connector-argocd-gcloud`, and publishes them on a merge to `main`.
