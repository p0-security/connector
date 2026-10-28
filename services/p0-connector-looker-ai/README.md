# p0-connector-looker-ai

The Looker (Agentic) connector grants and revokes access to the models of a
Looker (Google Cloud core) instance. It ships only as a GCP Cloud Run container
image.

Each grant gets its own Looker service account and its own secret. The
connector names the account after the secret, and finds it again by that name.
The secret holds the account's Looker API key, with a colon between the client
ID and the client secret:

```text
<client_id>:<client_secret>
```

The MCP server spec splits the secret at the colon with the gateway's
templates (`{{ credential.token | split: ":" | first }}` and `| last`), so
neither the gateway nor its API needs to know the format. The connector stores
a key only when both fields are letters and digits. That keeps the split exact,
and keeps anything else out of the MCP Toolbox's config. For any other key, the
connector deletes the account and fails the grant. Nothing documents what
Looker puts in a key (W4).

The key does not expire. A revoke removes access by deleting the account and
then the secret. A consumer signs in with the key (`POST /api/4.0/login`) and
gets an access token that lasts about an hour.

## What it does

The connector has one resource-root access, `model`.

- The **user** is the grant's secret name, as both the user body and the user
  id. It must be a Google Secret Manager secret id that starts with
  `p0_access-token_looker_`. The connector refuses any other name, so a call
  can't reach a Looker service account or a secret that isn't a Looker
  grant's.
- The **policy** is `{ model, level }`, where the level is `read` or `edit`.
  A `null` policy means no access.
- The **request context** holds the instance URL, where the Admin key is
  (`{ manager: "gcp", adminKeySecretId, projectId }`), and an optional
  `contentFolderId`, the folder the customer picked for content that agents
  save. The connector writes the grant secrets to the Admin key's project.

| Call                 | What it does in Looker and Secret Manager                                                                                                                                                                                   |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `identifyUser`       | Finds the Looker service accounts with the secret's name. Deletes any whose first name isn't `P0`, because a failed grant left it behind. With no finished account left, deletes the secret.                                |
| `provisionUser`      | Does what `identifyUser` does. If no account is left, creates one and its Looker API key, writes the key to the secret (creating the secret if needed), then names the account.                                             |
| `deleteUser`         | Deletes every Looker service account with the name, then the secret. An account or secret that is already gone is not an error.                                                                                             |
| `setPoliciesForUser` | Gives the account one role, P0's for the model and level, and reads its roles back. An edit grant first gets edit access on the agent content folder, so a missing folder fails it before the role. `null` takes both away. |
| `list`               | Lists the instance's models, leaving out hidden ones and ones with no Explore.                                                                                                                                              |

Looker shows an API key's secret once. If a step fails after `provisionUser`
creates the account, it deletes the account and the grant's secret, so the
next attempt starts over and no key outlives the failure.

`provisionUser` names the account only after it stores the key. The first name
is `P0` and the last name is the secret's name, so the first name marks a
finished account. Sometimes an unfinished account survives: the rollback
delete fails too, or Looker creates the account and its response never
arrives. The next call for the grant finds an account without `P0` as its
first name and deletes it.

Whenever no finished account is left, `identifyUser` also deletes the grant's
secret, since P0 doesn't call `deleteUser` for a user it can't find.

`deleteUser` deletes the account first, because the account is what gives
access. If the secret delete fails afterwards, the secret holds a key that no
longer works. P0 finds no account on its retry and doesn't call `deleteUser`
again, but `identifyUser` deletes the secret then.

## Roles

P0 creates these objects in Looker the first time a grant needs them, and
reuses them after that:

| Object         | Name                           | Holds                                  |
| -------------- | ------------------------------ | -------------------------------------- |
| Permission set | `p0-looker-ai-<level>`         | The level's permissions and parents    |
| Model set      | `p0-looker-ai-model-<model>`   | The one model                          |
| Role           | `p0-looker-ai-<model>-<level>` | That permission set and that model set |

- **read**: `access_data`, `see_looks`, `see_user_dashboards`,
  `see_lookml_dashboards`, `see_sql` and `explore`.
- **edit**: read's permissions plus `save_content`, `save_looks` and
  `save_dashboards`.

Looker permissions depend on other permissions. The connector reads the
dependencies from the instance (`GET /permissions`) and adds each permission's
parents. A grant fails when the instance doesn't list a permission, or when a
parent is one P0 never grants: `administer`, `deploy`, `develop`,
`manage_models` or `sudo` (W16).

A Looker admin can edit these objects, and every grant that reused an edited
one would get more or less than its level. So the connector compares each
object it finds with what it wants, and fails the grant on any difference,
naming it. It never changes or deletes an object, because other grants may use
it. When two grants race to create the same object, both use the one that wins.

`set_user_roles` replaces only the roles given to the account directly. Roles
the account gets from its groups stay, All Users included (W2, W6). The install
check lists them.

## Install check

`install.validation.get` takes the instance URL, where the Admin key is, and the
optional `contentFolderId`. It reports:

- whether Looker accepted the Admin key. If it didn't, the connector checks
  nothing else.
- how many models a grant can name
- the permissions a level needs that the instance doesn't list, and the refused
  permissions a level would pull in as parents
- the groups with roles that a new Looker service account joins
  (`include_by_default`), with their roles
- whether the agent content folder exists

## Admin key

The connector reads a Looker API key from the secret that `adminKeySecretId`
names. The value is JSON:

```json
{ "client_id": "...", "client_secret": "..." }
```

The key must belong to a Looker service account with the Admin role. Only a
Looker admin can create Looker service accounts and their API keys.

The connector reads the key on every call, signs in with it, and signs out when
the call ends. It sends the key only to the instance in the request context.
The URL must be `https://<instance>.looker.app`, and a redirect fails the call.
The connector refuses an instance behind a custom domain.

## Looker API limits

Looker (Google Cloud core) limits how many admin API calls an instance makes in
a month (10,000 on Enterprise). Signing in and out doesn't count. Every other
call the connector makes is an admin call (W31). Each call below starts with
the account search: 1 call for each page of 100 Looker service accounts. Each
page starts 10 accounts before the last one ended, so that an account deleted
during the search doesn't hide the next one. That is 1 call below 100
accounts, 2 from 100, and 1 more for every 90 after that.

| Call                        | Admin API calls after the search                                                     |
| --------------------------- | ------------------------------------------------------------------------------------ |
| `identifyUser`              | 1 for each unfinished account it deletes                                             |
| `provisionUser`             | As `identifyUser`, plus 3 when it creates the account                                |
| `deleteUser`                | 1 for each account it deletes                                                        |
| `setPoliciesForUser`, grant | 6, plus 1 for each of the 3 objects it creates. With a folder, 2 or 3 more           |
| `setPoliciesForUser`, none  | 1 for each account. With a folder, 2 more for each, and 1 for each record it removes |

`list` makes 1 call and no search. `install.validation.get` makes 2, plus the
group search, which pages like the account search, plus 1 with a folder.

The connector never retries a Looker call. A 429, or a 403 that names a quota
or a limit, becomes a `rate_limited` error whose message starts with
`Looker API limit reached.`

## Working assumptions

The connector was written before a Looker test instance existed, and none of it
has run against Looker yet. It follows Looker's API 4.0 spec (4.0.26.18) and
docs. The numbers refer to the design's working assumptions, which the live
test (INT-246) checks:

- **W2**: `create_service_account` takes a name and no roles, and
  `set_user_roles` replaces only an account's direct roles.
- **W3**: only `create_user_credentials_api3` returns a client secret, and only
  once.
- **W4**: Looker's client IDs and client secrets are letters and digits. A key
  with anything else fails the grant.
- **W5**: the MCP Toolbox may fail to start as an account with no first or last
  name, so the connector sets both with `update_user`. This also assumes that
  `update_user` accepts a Looker service account.
- **W6**: a new Looker service account joins All Users and every
  `include_by_default` group. The install check assumes All Users is one of
  those groups.
- **W11**: each level's permissions, with their parents, are enough for that
  level's tools.
- **W16**: Looker's API may accept a role that the role editor would refuse.
- **W17**: nothing short of the Admin role can make these calls.
- **W31**: the spec's `x-looker-activity-type` says which quota a call counts
  against: `none` for `login` and `logout`, and `non_query` (admin) for the
  rest.
- **W34**: Looker doesn't document what it returns when the monthly quota runs
  out.

Assumptions the design doesn't number:

- `/login` answers a key it doesn't accept with a 404. The spec lists a 404 for
  it, and no 401 or 403.
- `search_users` can't filter by a Looker service account's name, so the
  connector reads every Looker service account (`is_service_account=true`,
  sorted by id) and compares the names itself.
- Nothing says that Looker keeps those names unique.
- Looker doesn't document how it refuses a create whose name is taken. The
  connector treats a 409 as that refusal, and a 422 whose code is
  `already_exists` or whose message says the name is taken.
- Looker may refuse an access record on a folder that inherits its parent's
  access.

## Creating local builds

The build pulls P0's base images from a private Artifact Registry. Log in, and
register gcloud as a Docker credential helper for that host:

```bash
gcloud auth configure-docker us-west1-docker.pkg.dev
```

Then run this from the repository root:

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-looker-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-looker-ai-gcloud:dev .
```

## Deploying

The GCP service account that the Cloud Run service runs as needs these, in the
project that holds the secrets:

- `roles/secretmanager.secretAccessor` and `roles/secretmanager.viewer` on the
  Admin key secret, and on no other secret. P0 sends the secret id with each
  call, so a request could point the connector at any other secret its identity
  can read.
- `secretmanager.secrets.create` on the project, and
  `secretmanager.secrets.delete` and `secretmanager.versions.add` on the grant
  secrets. The connector never reads a grant secret back.

The service also needs to reach the Looker instance's public endpoint.
