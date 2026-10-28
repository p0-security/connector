# p0-connector-clickhouse

ClickHouse Cloud connector: gives a person access to one service in a
ClickHouse Cloud organization, just in time, through a custom role that P0
creates for the request with the person's own Cloud login as its only actor,
and deletes when the grant ends.

Ships as both an AWS Lambda container image and a GCP Cloud Run container
image, built from the same workspace with two different Dockerfiles.

## What it does

The connector acts for P0 on one or more ClickHouse Cloud organizations, each
through the Cloud API, as an API key the customer creates. It never creates a
database user, issues a credential or stores a secret.

It reads what it lists through P0's own Query API endpoints: saved, read-only
queries it creates on a service the first time it reads there, whose SQL is
fixed in `src/query/endpoints.ts`. A request's values only ever reach them as
typed `queryVariables`, never in the SQL.

It has two accesses, `sql` and `console`, each on one service. Granting a
ClickHouse database role isn't supported: ClickHouse Cloud refuses a
`GRANT <role>` in a policy's `tags.grants`.

### Install validation

`install.validation.get` takes the organization's ID and a pointer to the API
key's secret, and runs five checks in order. It fails at the first one that
doesn't pass, naming it in the error's `payload.step`. P0 runs it when an
organization is added. Nothing that comes later depends on it running
again: a lookup reads the live service listing, and puts P0's endpoints
back on a service when they've drifted, such as after a key rotation. It
checks the organization, not each service: it makes seven ClickHouse Cloud calls
however many services there are (more only when a listing runs to several
pages), and only the permission probes read a service:

1. `secret`: the connector can read the key's secret, and it holds the key's
   JSON.
2. `authenticate`: `GET /v1/organizations/{id}` answers with the key, and
   gives the organization's name. A 401 means the key was rejected. A 400,
   403 or 404 means the key is another organization's, or lacks
   `control-plane:organization:view`.
3. `permissions`: one probe per permission the key's role must hold. A 403
   counts as missing, and the check lists every one that's missing in
   `payload.missing`, space-separated. Extra permissions are ignored. With no
   services, the two service probes are skipped.
   `control-plane:service:manage-query-api-endpoints` has no probe that
   changes nothing, so it's first used when a lookup sets up P0's endpoints
   on a service, and a 403 there names it.
4. `services`: first the key's UUID, which P0's endpoints' `apiKeyIds` take,
   is found in `GET …/keys`: the one key whose `keySuffix` is the last 4
   characters of the key ID or of the key secret. None, or more than one,
   fails the check. Then every service gets a report from the organization's
   service listing alone. A BYOC service is `not-ready`. One older than
   ClickHouse 26.4, or whose version ClickHouse Cloud doesn't report, is
   `console-only`. Every other one is `ready`: P0 sets up its endpoints there
   the first time a lookup needs them. The reports keep the services' order.
   The check fails only when every service is `not-ready`, or there are
   none, with every service and its reason in the message and their IDs in
   `payload.notReady`: a `console-only` service still takes console role
   requests.
5. `domains`: the connector has a usable `DOMAIN_ALLOW_PATTERN`.

Once they all pass it returns the organization's name, the key's ID and UUID, the
pattern as deployed and each service's report, `{id, name, status}` with a
`reason` unless the status is `ready`.

### P0's Query API endpoints

| Endpoint     | Reads                                                         |
| ------------ | ------------------------------------------------------------- |
| `p0_objects` | Every database, table, view, materialized view and dictionary |

Each runs in database `system` as SQL console's read-only role
(`sql_console_read_only`), with no CORS origins, and only P0's key may run
it, by its UUID. An endpoint whose name doesn't start with `p0_` is never
read, changed or deleted.

A run is `POST` to the endpoint's own `url`, which must be
`https://queries.clickhouse.cloud/run/<uuid>`, with Basic auth,
`x-clickhouse-endpoint-version: 2` and `{"format": "JSONEachRow",
"queryVariables": {…}}`. The rows come back one JSON object per line.

A lookup sets up the endpoint it runs, the first time it runs it in a
connector call. It lists the service's endpoints once, and makes the
endpoint exactly its definition for the key:

- An endpoint missing by name is created, so the first lookup on a service
  creates it.
- One P0 created whose database, roles, CORS origins or keys differ in the
  listing is put back (`PUT`). After a key rotation, this is what moves the
  endpoint to the new key.
- Otherwise it's read whole, since the listing leaves out the SQL and the
  parameters, and put back when either differs. One whose SQL changed
  behind P0's back is never run as it is.
- What a create or update answers with is checked against the definition,
  at no extra call. The lookup fails as `unknown` when ClickHouse Cloud
  stored it other than as sent, and the endpoint isn't run.
- Another one P0 created with the same name is deleted.
- A create or update the key's role doesn't allow fails as
  `insufficient_privileges`, naming
  `control-plane:service:manage-query-api-endpoints`.

Nothing is kept between connector calls, so a repeat lookup on a service
makes three calls: the listing, the endpoint read whole, and its run (and a
fourth, the key listing, the first time a process needs the key's UUID). A run
that gets a 404 sets the endpoint up again and runs once more.

### Lookups

One `list` answers for every access. `list` gets no request context, so each
query carries the organization's credentials as `context`.

| `type`     | Takes       | One item per                  | `key`          | `value`      | `group` |
| ---------- | ----------- | ----------------------------- | -------------- | ------------ | ------- |
| `member`   | `email`     | member with the email         | user ID        | email        |         |
| `services` |             | service                       | service ID     | service name |         |
| `service`  | `serviceId` | field: `id`, `name`,          | field          | value        |         |
|            |             | `version`, `byoc`             |                |              |         |
| `objects`  | `serviceId` | database, table, view,        | `db`, `db.obj` | same as key  | kind    |
|            |             | materialized view, dictionary |                |              |         |

- `member` compares emails ignoring case. It's `[]` when no member has the
  email, refuses with `ambiguous_member` when more than one has, and refuses
  an email `DOMAIN_ALLOW_PATTERN` doesn't allow with `domain_not_allowed`,
  before any call.
- `service` is `[]` when the service isn't there. `version` is
  `clickhouseVersion`, or `""`. `byoc` is `"true"` or `"false"`. It reads
  the service alone: a lookup that runs an endpoint sets it up then.
- `objects` runs `p0_objects`. It leaves out `system`, `INFORMATION_SCHEMA`,
  `information_schema`, any database whose name holds a `.`, temporary
  tables, materialized views' `.inner.` and `.inner_id.` tables, and the
  `Dictionary` rows of `system.tables` (dictionaries come from
  `system.dictionaries`, once). Past 50,000 objects, or past 4 MiB of items
  as they're serialized (key, value, group and the JSON around them), it
  refuses rather than truncate, to stay under a Lambda's 6 MB response. The refusal says a whole-service request,
  `'*'`, still works.

### Views

The connector doesn't work out what a view reads. A request for a view or
materialized view grants that object only. Measured on ClickHouse
26.8.30.8:

- A view without `SQL SECURITY` reads as its invoker, so the grantee also
  needs `SELECT` on what it reads.
- A materialized view can't be `SQL SECURITY INVOKER`. One without
  `SQL SECURITY` needs `SELECT` on what its query reads, but not on its `TO`
  table.
- One with `SQL SECURITY DEFINER` needs nothing more, and neither does a
  view with `SQL SECURITY NONE`.

So a view that P0 users request should be `SQL SECURITY DEFINER`, or they
request its source tables too.

### Accesses

Each request gets one custom role, which P0 names `p0_…` and sends as both
the resource body and the resource ID. Every step finds the role by that
name in `GET …/roles`. The user is the requestor's email: P0 creates no
ClickHouse Cloud user, and the role's only actor is the organization member
with that email. Every call carries `{requestId, organization, serviceId,
description}`, where `organization` is the organization's credentials.

| Step                            | What the connector does                                                                                                                                           |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `createAccessResource`          | `POST …/roles` with the name, no actors and the base policies, unless the role is there already. Logs the request ID and description (roles have no description). |
| `addPoliciesToResource`         | Sets the role's policies to the base policies plus the access's.                                                                                                  |
| `bindAccessResource`            | Checks the email against `DOMAIN_ALLOW_PATTERN`, finds the one member with it, ignoring case, and sets the role's actors to `["user/<userId>"]`.                  |
| `unbindAccessResource`          | Sets the role's actors to `[]`. Never checked against the allowed domains.                                                                                        |
| `removePoliciesFromResource`    | Sets the role's policies back to the base policies, unless the role has no actors: then the delete comes next, and nothing is written.                            |
| `deleteAccessResource`          | Deletes the role. ClickHouse Cloud may take up to 10 minutes to remove the access.                                                                                |
| `provisionUser`, `identifyUser` | Answer with the email, with no call: a revoke works after the person has left the organization.                                                                   |

The base policies are `control-plane:organization:view` on
`organization/<orgId>` and `control-plane:service:view` on
`instance/<serviceId>`. P0 sends one policy per request, so "the base
policies plus the access's" is the whole role.

Every step reads the roles listing whole. One that says it has more pages
fails the step as `unknown`, so a revoke retries rather than take a role on
a later page as gone. A role the connector can't read is skipped, unless
it's the request's own role or the system role a `console` grant copies,
which fail the step as `unknown`. Another request's P0 role that can't be
read is skipped and logged, so it can't stop every revoke in the
organization.

Every step can run again. A step whose role is already as it should be
writes nothing, and a revoke step whose role is gone is done: one missing
from the listing, or one that a `PATCH` or `DELETE` answered with a 400 or a
404 and that's then missing from a second listing. Two roles with the same
name fail a grant step as `dependency_violation`, and a revoke step acts on
each of them. A grant step whose role is missing fails as
`object_not_found`. A missing role never fails a revoke step.

A role whose name doesn't start with `p0_` is never created, changed or
deleted. The framework refuses such a name before any step runs, and the
steps also refuse it themselves, as `not_p0_role`.

A bind refuses an email outside `DOMAIN_ALLOW_PATTERN` as
`domain_not_allowed` before any call, no member with it as `not_member`, and
more than one as `ambiguous_member`. It never reads or writes the member's
own roles.

#### `sql`

`{type: "sql", level, object: {database?, table?}}` becomes
`sql-console:database:access` on `instance/<serviceId>`, with one GRANT
statement per element of `tags.grants`: the level's privileges on the
object. A view is granted as itself only (see [Views](#views)).
On the whole service, `write` and `admin` end with a partial revoke of
every privilege beyond `read`'s on `system.*`, such as
``REVOKE INSERT, ALTER UPDATE, ALTER DELETE, TRUNCATE ON `system`.*``, so
the grantee can't delete or truncate ClickHouse's logs (`system.query_log`,
`system.session_log`), the evidence of what they did. Whether `tags.grants`
takes a REVOKE element is still to be checked on a live service.

| `object`            | Target                                                                    |
| ------------------- | ------------------------------------------------------------------------- |
| `{}`                | `*.*`                                                                     |
| `{database}`        | `` `database`.* ``                                                        |
| `{database, table}` | `` `database`.`table` `` (a table, view, materialized view or dictionary) |

| Level   | Privileges                                                     |
| ------- | -------------------------------------------------------------- |
| `read`  | `SELECT`, `dictGet`                                            |
| `write` | `read`'s, `INSERT`, `ALTER UPDATE`, `ALTER DELETE`, `TRUNCATE` |
| `admin` | `write`'s, `CREATE`, `DROP`, `ALTER`, `OPTIMIZE`               |

No level holds `ACCESS MANAGEMENT`, `GRANT OPTION`, `SYSTEM`, `KILL QUERY`,
named collections or `SOURCES`. The table is in `src/levels.ts`, and
`./connector` exports it as `CLICKHOUSE_LEVEL_PRIVILEGES`.

Read on the view `analytics.v_users`:

```json
{
  "allowDeny": "ALLOW",
  "permissions": ["sql-console:database:access"],
  "resources": ["instance/<serviceId>"],
  "tags": {
    "grants": ["GRANT SELECT, dictGet ON `analytics`.`v_users`"]
  }
}
```

Every name is backtick-quoted, with backslashes and backticks escaped.

#### `console`

`{type: "console", consoleRole}`:

- `sql-console-readonly` and `sql-console-admin` become
  `sql-console:database:access` on `instance/<serviceId>`, with
  `tags.roleV2` set to the console role.
- `service-reader` and `service-admin` copy the `control-plane:service:`
  permissions of the system role **Service Reader** or **Service Admin**,
  found by name ignoring case and read from `GET …/roles` as the grant
  runs, onto `instance/<serviceId>`: the ones it allows in one policy, and
  any it denies in another. Every other permission, `sql-console:*`
  included, is dropped. A system role that isn't there, is there twice, or
  gives no service permission fails as `dependency_violation`.

### What holds

- **Two hosts, and a closed list of calls.** The connector calls
  `api.clickhouse.cloud` and `queries.clickhouse.cloud` and nothing else, and
  only these Cloud API calls. Anything else is refused before it's sent.
  - `GET /v1/organizations/{organizationId}`
  - `GET …/members`
  - `GET …/keys`
  - `GET …/services` and `GET …/services/{serviceId}`
  - `GET` and `POST …/services/{serviceId}/query-api-endpoints`
  - `GET`, `PUT` and `DELETE …/query-api-endpoints/{endpointId}`, for an
    endpoint whose name starts with `p0_`
  - `GET` and `POST …/roles`
  - `PATCH` and `DELETE …/roles/{roleId}`, for a role whose name starts with
    `p0_`
- **Redirects are refused,** and a call is abandoned after 10 seconds, or 30
  for an endpoint run.
- **P0 never holds the key.** See [The API key](#the-api-key).
- **Calls are paced to the key's rate limit.** ClickHouse Cloud allows each
  API key
  [10 requests over a 10-second window](https://clickhouse.com/docs/cloud/manage/api/api-overview).
  Within one connector call, the connector sends at most 10 Cloud API calls
  in any 11 seconds (a second to spare), and reads the key listing once. The
  page doesn't say whether runs of Query API endpoints count, so they aren't
  paced. A call that gets a 429 is sent again after `Retry-After`, or 10
  seconds when it's absent. Once a wait would end more than 240 seconds into
  the connector call, well under the Lambda's 300, the connector stops: a
  429 goes back to P0 as `rate_limited`, with `retryAfter` from
  `Retry-After`, and a call whose turn is too late fails as `rate_limited`
  too. A large organization may need ClickHouse support to raise the key's
  limit.

### Refusals

A refusal P0 words in its own copy is a `validation_error` whose
`payload.reason` is one of a closed set (`src/refusals.ts`):
`ambiguous_member`, `domain_not_allowed`, `not_member` and `not_p0_role`.

### Errors

| ClickHouse Cloud                               | Connector error                               |
| ---------------------------------------------- | --------------------------------------------- |
| 401 or 403                                     | `insufficient_privileges`                     |
| The key's secret is missing, or can't be read  | `object_not_found`, `insufficient_privileges` |
| The secret is empty, or isn't the key's JSON   | `insufficient_privileges`                     |
| 404                                            | `object_not_found`                            |
| 429                                            | `rate_limited`, with `retryAfter`             |
| 5xx, or no answer, also while the body arrives | `upstream_unavailable`                        |
| 400 or 409                                     | `validation_error`, with ClickHouse's reason  |
| A body the connector can't read                | `unknown`                                     |

## The API key

The connector acts as one API key per organization, with two roles:

- the custom role `p0-connector`, with `control-plane:organization:view`,
  `control-plane:organization:manage`, `control-plane:service:view`,
  `control-plane:service:view-query-api-endpoints`,
  `control-plane:service:manage-query-api-endpoints` and
  `control-plane:organization:view-api-keys`;
- the system role **Basic Service API Reader**, which running an endpoint
  needs.

`organization:manage` is admin-equivalent: it lets the key create roles and
add anyone, itself included, to any role. The connector only ever
changes or deletes roles whose names start with `p0_`.

The key lives in the customer's own secret manager, AWS Secrets Manager or
Google Secret Manager, as a JSON object:

```json
{ "keyId": "<the API key ID>", "keySecret": "<the API key secret>" }
```

It's parsed strictly: no other fields, and neither value may hold whitespace.
Each call from P0 carries the organization's ID and a pointer to the secret,
never the key. The connector reads the secret with its own cloud identity on
every call, and sends the key as Basic auth. The key secret, the Basic
credentials and the `Authorization` header never go into a log line or an
error, and neither does the secret's name.

To rotate the key, create a new one with the same roles and store it as a new
version of the same secret. The next lookup on each service moves P0's
endpoints there to the new key. Then delete the old key.

P0 sends the secret's name with each call, so any other secret the
connector's identity can read is one a request could point it at. Grant it
the API key secrets of the organizations it serves and nothing else: never a
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
you, and it's case-sensitive. `acme\.com` also matches `notacme.com`, so write
`^acme\.com$`. One pattern covers every organization the connector serves.

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
  --build-arg WORKSPACE=@p0security/p0-connector-clickhouse \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-clickhouse:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-clickhouse \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-clickhouse-gcloud:dev .
```

This will set your locally-built images to have the tag `dev`. To publish and
deploy one, follow the steps in
[the Docker Hub connector's README](../p0-connector-docker/README.md#publishing-local-builds),
with `clickhouse` in place of `docker`. The deployment must set
`DOMAIN_ALLOW_PATTERN`, or the new image won't start.
