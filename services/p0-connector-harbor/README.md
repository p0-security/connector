# p0-connector-harbor

Harbor connector: gives a person a role on a [Harbor](https://goharbor.io)
project, or makes them a Harbor system administrator, just in time, and takes
it back when the grant ends.

Ships as both an AWS Lambda container image and a GCP Cloud Run container
image, built from the same workspace with two different Dockerfiles.

One connector serves any number of Harbor instances. Each call from P0 names
the instance, as `url`, and points at the secret that holds the instance's
admin credential, as `secret` (see "The admin credential"). `url` is a bare
`https` origin: no path, no query, and no username or password. The
instance's certificate has to be from a public CA.

## What it does

Two accesses work on every instance: `projectRole` (the three listers, grants
and revokes) and `systemAdmin`. Every Harbor call is made as the instance's
admin account, with an ID token minted from its credential. Install
validation runs every check below.

### Install validation

`install.validation.get` takes an instance, `{ url, secret }`, and checks, in
this order, that:

1. `secret`: the connector can read the secret, and its value is the admin
   credential.
2. `pattern`: `ALLOWED_EMAIL_DOMAIN_PATTERN` is set, and compiles.
3. `sign_in`: the identity provider mints an ID token from the credential.
4. `systeminfo`: the instance answers `GET /api/v2.0/systeminfo` as Harbor
   does. Harbor answers it for anyone, and up to 2.12.4 tells anyone its
   version. When the answer carries a version below 2.12.0, install fails
   here. The auth mode must be `oidc_auth`: Harbor accepts an ID token in no
   other mode, and with `db_auth` users set their own, unverified email.
5. `authenticate`: Harbor accepts the token, and its user is a system
   administrator: `GET /api/v2.0/users/current` answers 200 with
   `sysadmin_flag` set. A 401 is the `admin_token_rejected` refusal, and an
   unset flag `admin_not_harbor_admin`. Being an administrator through the
   identity provider's admin group isn't enough: the account is held to the
   flag, which a Harbor admin can see on the Users page. The body, which holds
   the user's CLI secret, is dropped by the parse.
6. `systeminfo`: the answer from step 4 carried a version, as Harbor's does
   for any caller it accepted. From 2.13.0 this is where the version is
   first known. It has to read as a version: three numbers, an optional `v`,
   an optional suffix.

An administrator holds every permission the accesses use, so nothing more is
probed. The messages quote a version only as the numbers the connector
parsed, and an auth mode only when it is one of Harbor's own: whatever
answered chose the rest.

It returns `harborVersion` and `authMode`, as Harbor reports them, and
`allowedEmailDomainPattern`, the pattern as it is set, less the whitespace
around it. Nothing of the credential or the token is reported.

The answer carries facts, not results, so a failed check fails the call. The
error's `payload.step` names the check, and `payload.host` the instance:

| `payload.step` | What happened                                                                                                                    | Error type                |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `secret`       | The secret doesn't exist, or holds no value yet.                                                                                 | `object_not_found`        |
| `secret`       | The secret manager refused the read.                                                                                             | `insufficient_privileges` |
| `secret`       | The secret manager limited the call: AWS's `ThrottlingException`, or a 429.                                                      | `rate_limited`            |
| `secret`       | The secret manager couldn't be reached, or answered with a 5xx.                                                                  | `upstream_unavailable`    |
| `secret`       | The read failed some other way.                                                                                                  | `unknown`                 |
| `secret`       | The secret's value isn't the admin credential.                                                                                   | `validation_error`        |
| `pattern`      | `ALLOWED_EMAIL_DOMAIN_PATTERN` is missing or blank, or doesn't compile.                                                          | `validation_error`        |
| `sign_in`      | The identity provider refused the refresh token: the `admin_signin_expired` refusal.                                             | `validation_error`        |
| `sign_in`      | The provider can't be reached, or refused some other way (see "The admin credential").                                           | as there                  |
| `systeminfo`   | The instance's host doesn't resolve, or its certificate isn't one the connector trusts.                                          | `validation_error`        |
| `systeminfo`   | The instance gave no answer within 10 seconds, or the connection failed some other way.                                          | `upstream_unavailable`    |
| `systeminfo`   | Something in front of Harbor refused the call with 401 or 403. Harbor itself answers this route for anyone.                      | `insufficient_privileges` |
| `systeminfo`   | The instance answered 429.                                                                                                       | `rate_limited`            |
| `systeminfo`   | The instance answered with a 5xx.                                                                                                | `upstream_unavailable`    |
| `systeminfo`   | The answer wasn't Harbor's: any other status, a redirect included, a body over 1 MiB, or a body that isn't Harbor's system info. | `validation_error`        |
| `systeminfo`   | Harbor didn't tell the connector its version, although it accepted the token.                                                    | `validation_error`        |
| `systeminfo`   | Harbor is older than 2.12.0, or its version doesn't read as one.                                                                 | `validation_error`        |
| `systeminfo`   | Harbor's auth mode isn't `oidc_auth`.                                                                                            | `validation_error`        |
| `authenticate` | Harbor didn't accept the ID token (401): the `admin_token_rejected` refusal.                                                     | `validation_error`        |
| `authenticate` | The token's user doesn't have `sysadmin_flag`: the `admin_not_harbor_admin` refusal.                                             | `validation_error`        |
| `authenticate` | `/users/current` failed some other way, or gave no answer: the same types as the `systeminfo` rows above.                        | as above                  |

A failed read of the secret says what failed by its code or its HTTP status
when it has one, on both clouds, and never by its own text. The connector
logs the failure's name, code, status and, on AWS, the request id, and
nothing of the pointer but its manager.

A secret manager can refuse a read of a secret that doesn't exist the same
way as one the connector may not read, when the connector's grant covers only
the secrets it should. So a mistyped name may show up as
`insufficient_privileges`, and that message says to check the name too.

### The member lister

`list` with `{ type: "member", context: { url, secret }, email }` finds the
Harbor user whose email is `email`:

1. The domain allowlist (below) checks the email first, before the secret is
   read or Harbor is called.
2. `GET /api/v2.0/users?email=<email>`, every page. Harbor's filter is a
   substring match, so only the users whose email equals `email`, ignoring
   ASCII case only, count: `bob@example.com` doesn't find
   `jimbob@example.com`, and `kate@example.com` doesn't find an email spelled
   with the Kelvin sign `K` (U+212A), which Unicode case folding would.
3. No user is `[]`, and P0 words that refusal, since it knows the instance's
   id and URL. One user is `[{ key: "<user id>", value: "<username>" }]`.
   More than one, emails that differ only in case, is a `validation_error`:
   "More than one Harbor user on `<host>` has the email `<email>`. Ask a
   Harbor admin to remove the duplicate." `payload.userIds` lists the
   matching users' ids, comma-separated, for the admin.

The user list refuses a token Harbor doesn't accept with a 401, so the lookup
proves the token too.

### The project lister

`list` with `{ type: "project", context }` lists every project on the
instance, as `{ key: <name>, value: <name> }`. It proves the token first:
Harbor answers a token it doesn't accept as an anonymous caller, and would
list the public projects only.

With a `project` as well, it asks about that one project and answers `[]` or
its one row: `HEAD /api/v2.0/projects?project_name=<project>` says whether it
exists. The admin account sees every project, so there is no scope to check.

### The direct-role lister

`list` with `{ type: "direct-role", context, project, userId }` answers the
role the user holds directly on the project: `[]`, or
`[{ key: <role>, value: <role> }]`. It pages the project's members and stops
on the user's own row (`entity_type` `u`). A group's row never counts, even
one whose group id equals the user id: P0 manages direct membership only.

`[]` means "held no direct role", so nothing else answers `[]`:

- A project that doesn't exist is the `project_gone` refusal.
- A row whose role id isn't one of Harbor's five is a `validation_error`
  naming the id. Harbor stores any role id a `PUT` sends.

### Grants and revokes

`setPoliciesForUser` takes exactly one policy, `{ project, role }`, for the
user id P0 resolved at request time. Anything else is an `unknown` error: a
P0 bug.

A grant (`role` set):

1. The email in the request context must pass the domain allowlist, before
   the secret is read, a token is minted or Harbor is called.
2. The user list must give exactly that user for the email, ignoring ASCII
   case. No user, or another one, is the `no_user` refusal ("The Harbor user
   for `<email>` on `<host>` no longer exists, or its email changed. Request
   access again."); two are `duplicate_email`.
3. The user's own member row is added with the role, or raised to it. A grant
   never lowers: one that finds an equal or higher direct role succeeds
   without a write, and the revoke at expiry then removes or lowers a role P0
   never gave. P0 refuses such a request at request time, and again when it
   stages the grant. A role someone raises outside P0 between the stage and
   the grant is accepted drift: it is lowered or removed with the request. A
   409 on the add means a row appeared since the read; it is read again and
   raised.
4. The row is read again, and the grant fails unless it holds at least the
   role: Harbor answers 200 to a write on a member id that isn't the
   project's.

A revoke (`role: null`) checks neither the domain nor the user list, so
taking access away never depends on them. It only ever lowers:

- With no `priorRole`, the user's own row is removed, whatever role it
  holds.
- With a `priorRole` that ranks below the role the user holds now, that role
  is put back. An equal or higher one leaves the row as it is.
- No row is already revoked. So is a project that no longer exists, once
  Harbor itself says so: the system info has to answer as Harbor's, and
  `HEAD /projects?project_name=` has to say 404. A 404 from a proxy, or for
  a project that exists, fails the revoke instead.
- With a `priorRole`, a row whose role id isn't one of Harbor's five is a
  `dependency_violation` naming it, and nothing changes: P0 can't tell
  whether the prior role ranks below it.
- The row is read again after the write, as for a grant.

A revoke is bound to nothing P0 granted: the connector can't tell whether the
role it lowers or removes is one P0 gave, only that P0 says its grant is over.
Reading the row, comparing and writing isn't atomic, since Harbor has no
conditional write. P0's lock on the user body is what keeps two calls for one
user apart.

Harbor stores any role id a `PUT` sends. Its member list is believed to leave
out a row whose role id isn't one of its five, because it inner-joins the
role table. That is read from Harbor's source, not checked on a live Harbor.
If so, the connector can't see such a row: a grant fails on Harbor's 409 with
a message saying so, and a revoke reports it done. The refusals above for an
unknown role id are for a Harbor that does list such a row, such as a later
version with a sixth role.

Every call is the admin account's, so a grant or a revoke also fails with the
admin credential's refusals: `admin_signin_expired` when the provider refuses
the refresh token, `admin_token_rejected` on Harbor's 401, and
`admin_not_harbor_admin` on its 403. Until someone signs the admin account in
again, P0 can neither grant nor take access back.

A group's row is never read as the user's or changed. `identifyUser` answers
the user id P0 sends, without calling Harbor, so P0's `provisionUser` never
reaches `createUser`, which refuses: the connector never creates Harbor users.
`deleteUser` does nothing, because a revoke calls it after putting the prior
role back.

### Roles

Roles go by Harbor's names. `src/harbor/roles.ts` maps them to Harbor's ids
both ways (projectAdmin 1, developer 2, guest 3, maintainer 4, limitedGuest 5) and ranks them by what they hold: limitedGuest, guest, developer,
maintainer, projectAdmin. The ids aren't in that order, so nothing ranks by
id.

### Refusals

A refusal P0 words in its own copy carries a `payload.reason` from a closed
set: `domain_not_allowed`, `domain_pattern_unusable`, `duplicate_email`,
`no_user`, `project_gone`, `admin_signin_expired`, `admin_token_rejected` and
`admin_not_harbor_admin`. `./connector` exports the set as
`HARBOR_REFUSAL_REASONS`, and as the zod enum `harborRefusalReason` to parse a
payload with. A new reason is a change to the contract. Any other
`validation_error` carries no reason, and P0 passes it through with its own
message. In the connector, every refusal with a reason is built by
`refusal()` (`src/refusals.ts`), whose `reason` is typed to the set.

### The system administrator access

`systemAdmin` gives a person Harbor's system administrator flag
(`sysadmin_flag`) and takes it back at expiry. A system administrator has full
control of the registry: every project, every robot account, every user, and
Harbor's configuration, the OIDC client's included. P0's policy for who may
request it, and who approves, should be as strict as for any admin of the
registry.

Harbor lets only a system administrator change the flag: from 2.13.6, 2.14.5
and 2.15.3, `PUT /users/{id}/sysadmin` answers anyone else 403, a robot
account included, whatever its permissions
([GHSA-w5fq-xrhj-j7g2](https://github.com/goharbor/harbor/security/advisories/GHSA-w5fq-xrhj-j7g2)).
The connector calls as the instance's admin account, so the access works on
patched Harbor, and on every instance.

Its request context is:

```
{ url, secret, requestId, email, wasSystemAdmin }
```

`wasSystemAdmin` is whether the user had the flag before P0 granted, as P0
read it at stage. It is required, and `null` doesn't parse: a context that
lost it must fail, not read as "wasn't" and take the flag from someone who
had it.

`list` with `{ type: "admin-state", context, email }` reads the user list as
`member` does: the allowlist first, then every page of Harbor's substring
matches, keeping the exact ones, with two or more the `duplicate_email`
refusal. It answers `[]` for no user, or `[{ key: <user id>, value: <state> }]`,
where the state is `none`, `flag`, `auth` or `flag_and_auth`. `auth` is
admin through the identity provider's admin group (`admin_role_in_auth`).
Harbor works that out only for the signed-in user and the user list always
answers it `false`, so in practice the state is `none` or `flag`.
`./connector` exports the states as `harborAdminState`.

`setPoliciesForUser` takes exactly one policy, `{ systemAdmin: boolean }`.

A grant (`systemAdmin: true`):

1. A grant whose context says `wasSystemAdmin: true` is refused, before any
   secret is read: the revoke would leave the flag in place, so if the flag
   was cleared since the stage, the grant would never end. P0 refuses a
   request from an administrator before it gets here.
2. The email must pass the domain allowlist, before any secret is read or
   Harbor is called.
3. The user list must give exactly the user P0 resolved for the email, as
   for a project role (`no_user`, `duplicate_email`). That read gives the
   user's flag too: a user who has it already is left as they are, with no
   write. P0 refuses such a request before it gets here.
4. It sends `PUT /api/v2.0/users/{id}/sysadmin` `{"sysadmin_flag": true}`. A
   404 there is `no_user`.
5. It reads the user again through the user list, by `q=user_id=<id>`, and
   fails with `dependency_violation` unless the flag is set.

A revoke (`systemAdmin: false`) checks neither the domain nor the email, and
never sets the flag:

- With `wasSystemAdmin: true`, it does nothing: no secret is read and Harbor
  isn't called.
- A user without the flag, or who no longer exists, is already revoked.
- Otherwise it clears the flag, and reads the user again.
  A 404 on the write is done once the user list agrees the user is gone. A
  flag still set fails with `dependency_violation`.

As for a project role, the revoke can't tell whether the flag it clears is
one P0 set, and P0's lock on the user body is what keeps two calls for one
user apart. `identifyUser` answers the user id without calling Harbor, and
`deleteUser` does nothing.

Harbor's 401 and 403, and the provider's refusal, are the same refusals as
for a project role.

## Calling Harbor

Every Harbor call goes through `src/harbor/api.ts`. Each call has a 10-second
deadline, its body included, and follows no redirect, since it carries the
ID token as `Authorization: Bearer`. It reads the body of a 2xx answer only, and no more than 1 MiB of
it: a full page of 100 projects, the largest answer the connector asks for,
is well under 100 KiB. It sends `X-Is-Resource-Name: true`, so Harbor reads a
project's name as a name even when it looks like an id, and no cookie.

Listings ask for 100 rows a page and stop on the first shorter page. They
never trust `X-Total-Count`, which counts rows Harbor's members list doesn't
return, and give up after 1,000 full pages.

The client (`src/harbor/client.ts`) absorbs Harbor's traps, so a caller
can't fall into them:

- Harbor treats a token it doesn't accept as an anonymous caller, and still
  answers `GET /projects` for one, with the public projects. So listing
  projects proves the token first, with the user list.
- Harbor answers 403 for a project that doesn't exist, the same as for a
  caller who may not touch it. So a 403 on a project's route asks
  `HEAD /api/v2.0/projects?project_name=`, and a project that doesn't exist,
  or a 404 (a delete that landed between Harbor's two lookups of the
  project), fails the call as `project_gone`, never as "not an
  administrator" or "not Harbor".
- The user list's `email` filter matches a substring, ignoring case. So a
  lookup keeps only the users whose email is the one asked for, ignoring
  case, and refuses an empty one, which would match everyone.

A call that gets no answer, or an answer Harbor wouldn't give, is logged as a
warning with the reason. A status outside 2xx is logged at debug only: the
caller decides what it means, and the route logs what reaches P0.

A failed call becomes a `ConnectorError` whose message names the call by its
route (`GET /api/v2.0/projects/{project_name}/members`), never its path or
query, and never quotes Harbor's answer. `payload` holds `host` and, when
there is one, `status` or Node's `code`; a `project_gone` holds the `project`
and `reason: "project_gone"`, which is how a revoke recognises it and treats
it as done. It is a `validation_error`, not `object_not_found`, because P0
shows the requester only "Not found" for the latter.

| Harbor's answer                                                                                      | Error type                                          | Message                                                |
| ---------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------ |
| 401                                                                                                  | `validation_error`, reason `admin_token_rejected`   | Harbor didn't accept the admin account's ID token.     |
| 403                                                                                                  | `validation_error`, reason `admin_not_harbor_admin` | The admin account isn't a Harbor system administrator. |
| A project that doesn't exist (`project_gone`)                                                        | `validation_error`                                  | Project `<name>` no longer exists on `<host>`.         |
| 409                                                                                                  | `already_exists`                                    |                                                        |
| 429                                                                                                  | `rate_limited`                                      |                                                        |
| 5xx, or no answer                                                                                    | `upstream_unavailable`                              |                                                        |
| 400, 405, 412 or 422                                                                                 | `validation_error`                                  | Harbor refused the call.                               |
| A host that doesn't resolve, a certificate not trusted                                               | `validation_error`                                  | What the customer has to fix.                          |
| Any other status, redirects and a 404 off a project's route included, or a body Harbor wouldn't send | `validation_error`                                  | The URL doesn't point at Harbor.                       |

## The admin credential

The connector acts as a dedicated Harbor admin user, for every Harbor call:
user lookups, project roles and system administrator. Harbor accepts
`Authorization: Bearer <ID token>` on its API, in OIDC mode, when the token's
audience is Harbor's OIDC client and its subject and issuer belong to a
Harbor user (`src/server/middleware/security/idtoken.go`). The connector mints
that token itself from a refresh token: once per connector call, reused by
every Harbor call that connector call makes, and never kept between calls.

The customer sets it up once:

1. Create a dedicated user in the identity provider, such as
   `harbor-automation@<domain>`. Sign it in to Harbor once, which creates the
   Harbor user, and make it a Harbor administrator on the Users page. The
   flag, not the identity provider's admin group: install validation checks
   the flag.
2. Add a client secret for P0 to Harbor's OIDC client, so it can be revoked
   on its own without touching Harbor's. Where the provider allows only one
   secret, use Harbor's own.
3. Get a refresh token for that user from Harbor's OIDC client, with the
   `openid email` scopes and offline access (`access_type=offline` at Google,
   the `offline_access` scope at most others).
4. Store the credential as the instance's secret, in AWS Secrets Manager or
   Google Secret Manager:

```json
{
  "issuer": "https://accounts.google.com",
  "clientId": "<Harbor's OIDC client ID>",
  "clientSecret": "<a client secret of Harbor's OIDC client>",
  "refreshToken": "<the admin user's refresh token>"
}
```

Each call from P0 carries a pointer to the secret, as `secret`, never the
credential:

- `{ "manager": "aws", "region": "<region>", "secretId": "<name or ARN>" }`
- `{ "manager": "gcp", "projectId": "<project>", "secretId": "<name>" }`

The connector reads the secret with its own cloud identity on every call, and
keeps nothing between calls: a new version of the secret takes effect on the
next call. It parses it strictly: exactly those four fields, `issuer` an https
URL without a query or fragment, and the other three non-empty, on one line. A
refusal names the fields that are wrong by these names, and never a value or a
field it doesn't know.

An earlier version of the connector used a Harbor robot account. It doesn't
any more: a robot account made for it can be deleted in Harbor, and its
secret in the secret manager with it.

Harbor has to sign users in with OIDC: it accepts an ID token in no other
mode. LDAP-mode Harbor is no longer supported, and `db_auth` never was.

On each call the connector reads `<issuer>/.well-known/openid-configuration`,
checks that the document's `issuer` is the one in the secret, and posts the
`refresh_token` grant to its `token_endpoint`, which must be https. The
client authenticates with HTTP basic auth, or in the form when the provider
says it takes only that. Every call to the provider follows no redirect, has
the same 10-second deadline as Harbor's, and reads at most 1 MiB. The ID
token is held to the form of a JWS, at most 16 KiB, and lives only in the
client that sends it. The refresh token, the client secret and the ID token
never go into a log line or an error, and nor does anything the provider
says but its status and a standard OAuth error code.

The provider's refusals:

| What the provider answers                    | Error                                                                            | What to do                                                       |
| -------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `invalid_grant`                              | `validation_error`, reason `admin_signin_expired`                                | Sign the admin account in again and store the new refresh token. |
| `invalid_client` or `unauthorized_client`    | `validation_error`                                                               | Check the client ID and secret.                                  |
| A 2xx without an ID token                    | `validation_error`                                                               | Get the refresh token again, with the `openid` scope.            |
| A discovery document that isn't the issuer's | `validation_error`, `payload.step` `discovery` (`sign_in` in install validation) | Check `issuer`: it is the issuer in Harbor's OIDC settings.      |
| 429, a 5xx, or no answer                     | `rate_limited`, `upstream_unavailable`                                           | Try again.                                                       |

The risk: the admin user is a Harbor system administrator, so the connector
holds full control of the registry, and the refresh token and the client
secret are together as sensitive as an admin's password. Anyone who holds
both can sign in to Harbor as an administrator. Keep them in the secret
alone, grant the read to the connector's identity alone, and revoke the
refresh token or the user's sessions to cut the connector off. Revoke the
client secret only when it is P0's own: Harbor signs people in with its own.

The refresh token can stop working. Identity providers expire refresh tokens
on their own schedule: Google Workspace's session control and
reauthentication policies, an idle timeout, at some providers a password
change, or the user being suspended. The connector can't renew it, since it only reads the
secret. It then fails every call, grants and revokes of both accesses
included, with `admin_signin_expired`, and install validation fails at
`sign_in`, until someone signs the admin account in again and stores the new
refresh token as a new version of the secret. Nothing warns ahead of time: a
refresh token carries no expiry the connector can read. A provider that rotates refresh tokens on use would stop working
after the first call: the connector logs a warning when the provider sends a
new refresh token back. Turn rotation off for Harbor's client.

## The secret manager

The credential, the ID token and the `Authorization` header never go into
one of the
connector's own log lines or errors. Nothing of the pointer but its manager
does either, the secret's id least of all: on AWS it is any string, so a
credential pasted where the name goes would travel with the message. A
failure the connector didn't expect is described by its code, never by its
own text.

That promise covers the connector's own log lines. On Cloud Run the
platform's request log records the URL of every call, and P0 sends a query's
input in the URL, so the pointer, secret id included, is in that log.

P0 sends the secret's name with each call, so any other secret the connector's
identity can read is one a request could point it at. Grant it the admin
credential secrets of the instances it serves and nothing else: never a wildcard that
could match another secret, and never a grant at the account or project level.
The call names the instance too, so the host the ID token is sent to also
comes from P0, and the connector only holds it to a bare `https` origin.

### AWS Secrets Manager

The Lambda's execution role needs `secretsmanager:GetSecretValue` on each
secret's full ARN. If a secret is encrypted with a customer-managed KMS key,
the role also needs `kms:Decrypt` on that key.

### Google Secret Manager

The Cloud Run service account needs two roles, both bound on the secret:
`roles/secretmanager.secretAccessor` and `roles/secretmanager.viewer`.

The accessor role isn't enough on its own. The shared secret client
(`@p0security/secret-manager-client`) reads the latest version's value, then
reads that version's metadata, and the second call needs
`secretmanager.versions.get`, which the accessor role doesn't have. Without
it the read is refused, and the connector reports that it isn't allowed to
read the secret.

## The domain allowlist

The connector only looks up, or gives access to, an email whose domain
`ALLOWED_EMAIL_DOMAIN_PATTERN` allows. The pattern is the connector's own:
P0 never stores or sends it, so nothing in a call can widen it.

- The pattern is matched against the domain only, the text after the `@`, and
  has to match all of it. The connector adds the anchors itself, so write the
  pattern without them: it reads `p0\.dev|p0security\.com` as
  `^(?:p0\.dev|p0security\.com)$`. Anchors you add are harmless.
- Escape the dots: an unescaped `.` matches any character.
- Case doesn't matter.
- A subdomain is allowed only when the pattern says so, as
  `([a-z0-9-]+\.)*p0\.dev` does.
- Avoid nested quantifiers such as `(a+)+` or `(.+\.)+`. The regex runs on
  every domain a request names, and a pattern like that can take seconds on a
  long one that almost matches.
- An address that isn't exactly `<local>@<domain>` is refused, a quoted local
  part with an `@` in it included.
- While the pattern is unset, blank or doesn't compile, every email is
  refused, the connector logs a warning saying why, and install validation
  fails. The pattern has to compile on its own, before the connector wraps
  it.
- It is read on every call, so a changed pattern applies from the next one.
- One pattern covers every Harbor instance the connector serves. An instance
  that needs other domains needs its own connector.

A refused email is a `validation_error` with `payload.reason`
`domain_not_allowed`, or `domain_pattern_unusable` when the pattern is the
problem. Removing access never consults the pattern. No message quotes the
pattern or the regex engine's error, since messages reach requesters: the
warning in the connector's log has the engine's error.

The rule is a copy of the Databricks connector's (`DOMAIN_PATTERN` there),
kept close to it so the two can become one shared rule later.

## Configuration

The connector reads its configuration from environment variables, which the
customer's Terraform sets on the deployment.

| Variable                       | What it is                                                                                                                                          | Required       |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| `ALLOWED_EMAIL_DOMAIN_PATTERN` | A regular expression for the email domains that may receive access. P0 never stores or sends it. See [the domain allowlist](#the-domain-allowlist). | Yes            |
| `CONNECTOR_AUDIENCE`           | The audience P0 mints the ID token for: the service URL the Cloud Run API reports as `uri`. Without it the Cloud Run service refuses to start.      | Cloud Run only |
| `INVOKER_SA_EMAIL`             | The service account allowed to call the connector, which is P0's. Without it the Cloud Run service refuses to start.                                | Cloud Run only |
| `LOG_LEVEL`                    | The pino log level. Defaults to `info`.                                                                                                             | No             |

On Cloud Run the caller sends a Google ID token as a bearer token, and the
connector accepts it only when its `email` claim is `INVOKER_SA_EMAIL` and
its `aud` claim is exactly `CONNECTOR_AUDIENCE`. `/health` answers without a
token. A Lambda checks no token: IAM decides who may invoke the function.

The Cloud Run service listens on `PORT`, 8080 when unset.

The connector needs a network route to the secret manager as well as to each
Harbor instance. The read of the secret has no deadline of its own, so the
function's or the service's timeout has to sit above the Harbor call's 10
seconds plus the read.

The image build sets `GIT_REF`, `BUILD_DATE` and `WORKSPACE`, which the
connector reports as its metadata.

## Running it locally

Both entry points run on a laptop, with no image and neither cloud. They need
something to stand in for Harbor and for the secret manager:

- **Harbor and the identity provider.** A Harbor you can reach with its
  OIDC provider, or any `https` server that answers what install validation
  reads, as [`dev/stub-harbor.mjs`](dev/stub-harbor.mjs) does: an OpenID
  provider under `/idp` that mints a fake ID token, and Harbor's system info,
  the user list, `/users/current` (an administrator) and the project list. For a self-signed
  certificate, give the connector `NODE_EXTRA_CA_CERTS=<cert.pem>`. Don't set
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, and don't look for an `http` switch: there
  isn't one.
- **AWS Secrets Manager.** The AWS SDK honours
  `AWS_ENDPOINT_URL_SECRETS_MANAGER`, so a local server that answers
  `GetSecretValue` will do, with any `AWS_ACCESS_KEY_ID` and
  `AWS_SECRET_ACCESS_KEY`.
- **Google Secret Manager.** There is no local stand-in. The client uses
  Application Default Credentials against the real API, so reading a `gcp`
  pointer needs a real project.

[`dev/`](dev) has a stand-in for each of the first two, with fake
credentials: `stub-harbor.mjs` on `https://localhost:8443` and
`stub-secrets.mjs` on `http://127.0.0.1:4566`, which holds an admin
credential named `harbor-admin`. The top of each file says how to run it. Neither is in an
image.

The commands below assume those two are running. Run them from the
repository root.

Build the workspace and the workspaces it depends on:

```bash
yarn workspaces foreach --recursive --topological --from @p0security/p0-connector-harbor run build
```

### GCP Cloud Run

This is the command the Cloud Run image runs. Cloud Run mode always verifies a
Google-signed ID token, so set `INVOKER_SA_EMAIL` and `CONNECTOR_AUDIENCE`,
and send an ID token for that service account with that audience. Any service
account you hold `roles/iam.serviceAccountTokenCreator` on will do. The
[AWS Lambda](#aws-lambda) entry point below takes no token.

```bash
env PORT=18080 ALLOWED_EMAIL_DOMAIN_PATTERN='example\.com' \
  INVOKER_SA_EMAIL=<invoker-sa-email> CONNECTOR_AUDIENCE=http://127.0.0.1:18080 \
  AWS_ENDPOINT_URL_SECRETS_MANAGER=http://127.0.0.1:4566 \
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  NODE_EXTRA_CA_CERTS=/absolute/path/to/cert.pem \
  yarn workspace @p0security/p0-connector-harbor run p0-connector-harbor
```

Then, from another shell:

```bash
curl -s http://127.0.0.1:18080/health

ID_TOKEN=$(gcloud auth print-identity-token --include-email \
  --impersonate-service-account=<invoker-sa-email> \
  --audiences=http://127.0.0.1:18080)
curl -s -H "Authorization: Bearer $ID_TOKEN" "http://127.0.0.1:18080/trpc/harbor.install.validation.get?input=$(node -p 'encodeURIComponent(JSON.stringify({ url: "https://localhost:8443", secret: { manager: "aws", region: "us-west-2", secretId: "harbor-admin" } }))')"
```

### AWS Lambda

The Lambda image runs `handler` from the bundle, which is a plain async
function, so it needs no Lambda runtime. It takes the HTTP request P0 would
have sent. A query's input goes in the URL. A mutation is a `POST` with the
input as its `body` and `"content-type": "application/json"` in `headers`.

```bash
yarn workspace @p0security/p0-connector-harbor build-within-docker

env ALLOWED_EMAIL_DOMAIN_PATTERN='example\.com' \
  AWS_ENDPOINT_URL_SECRETS_MANAGER=http://127.0.0.1:4566 \
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  NODE_EXTRA_CA_CERTS=/absolute/path/to/cert.pem \
  node --input-type=module -e '
    const { handler } = await import("./services/p0-connector-harbor/dist/index.mjs");
    const input = encodeURIComponent(JSON.stringify({ url: "https://localhost:8443", secret: { manager: "aws", region: "us-west-2", secretId: "harbor-admin" } }));
    console.log(JSON.stringify(await handler({ url: "https://x/trpc/harbor.install.validation.get?input=" + input, method: "GET", headers: {} })));
  '
```

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
  --build-arg WORKSPACE=@p0security/p0-connector-harbor \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-harbor:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-harbor \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-harbor-gcloud:dev .
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

docker tag p0-connector-harbor:dev \
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

docker tag p0-connector-harbor-gcloud:dev \
  "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-harbor-gcloud:dev"

docker push "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-harbor-gcloud:dev"
```

## Deploying a new connector image

If you already have a Lambda function set up, go to the AWS Console and deploy
the function from the newly pushed image.

If you already have a Cloud Run service set up instead, go to the GCP Cloud
Console and deploy a new revision from the newly pushed image.

Either way, the deployment must set `ALLOWED_EMAIL_DOMAIN_PATTERN`, and a
Cloud Run service must also set `INVOKER_SA_EMAIL` and `CONNECTOR_AUDIENCE`.
