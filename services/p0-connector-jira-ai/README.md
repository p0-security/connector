# p0-connector-jira-ai

Jira (AI) connector. It puts a pool service account in a Jira project role
for an AI agent's request, copies that account's API key into the request's
own secret, and undoes both when the request ends.

It runs on GCP Cloud Run only, under a service name the customer chooses. P0
builds against its contract, `@p0security/p0-connector-jira-ai/connector`.

## Calling Jira

Every call from P0 names the site:

- `cloudId`: the site's Atlassian cloud id, a UUID.
- `adminClientId`: the OAuth client id of the site's admin service account.
- `adminSecret`: the secret that holds that client's secret, as
  `{ manager: "gcp", projectId, secretId }`. The secret's whole value is the
  client secret.
- `tenantId`: the P0 organization the call is for, 1 to 128 letters, digits,
  `_` or `-`. Only one P0 organization can manage a site's P0 roles.

The connector exchanges the client secret at
`https://auth.atlassian.com/oauth/token` (`grant_type=client_credentials`)
and keeps the token in memory until a minute before it expires. Jira calls go
to `https://api.atlassian.com/ex/jira/{cloudId}/rest/api/3`.

Every Atlassian call, the token exchange included, goes through
`callAtlassian` in `src/jira/atlassian-call.ts`. It retries a 429, a 5xx, a
network failure or a timeout up to 4 attempts per call, each attempt for up
to 10 seconds, waiting out `Retry-After` when Atlassian sends one and an
exponential backoff with jitter otherwise.

One connector request that calls Jira (a role grant or revoke, or an install
lookup) has a 30-second budget, which starts before it reads the admin client
secret. The secret read, the token exchange and every Jira call, attempts and
waits together, share it. When a retry would pass the budget, the call fails
with `rate_limited` or `upstream_unavailable`, and a secret read that hasn't
finished fails with `upstream_unavailable`. Each asks to try the request again
in a few minutes. P0 holds its pool lock for 60 seconds while it calls the
connector. Some of that goes before the budget starts: P0 finds the
connector and signs its ID token, and Cloud Run may start a cold instance. The
other 30 seconds leave room for those.

A `POST` is retried only where a repeat is safe: adding a role member again
changes nothing, a repeated role create finds the role on a re-list, and a
scheme grant Jira refuses as already present (400) counts once a re-list
shows it.

## Install lookups

- `install.site.get` takes `{ site }` and returns `{ jiraAdmin }`: whether the
  site's admin account holds the Administer Jira global permission. It calls
  `GET /rest/api/3/mypermissions?permissions=ADMINISTER` as that account.
  When the account holds it, the lookup also claims the site for the P0
  organization: it finds or creates both of P0's roles with that
  organization in their description. It fails with `validation_error` if
  another P0 organization manages P0's roles there. So the first P0
  organization to verify a site holds it, before its first grant.
- `install.account.get` takes `{ site, email }` and returns `{ accountId }`.
  It fails with `object_not_found` unless exactly one account matches.
- `install.project.get` takes `{ site, projectKey }` and returns
  `{ style, roles }`. `style` is `company-managed` for Jira's `classic`
  style and `team-managed` otherwise. `roles` is every role the project
  lists, as `{ id, name }`. P0 offers them as the roles an agent can request
  in a team-managed project.

## `role` access

The user is an existing account, `{ cloudId, accountId }`, and the connector
never creates or deletes it. `setPoliciesForUser` gets the full set of roles
the account should hold on the request's project. Each policy is one of:

- `{ type: "p0", level: "read" | "write" }`, for a company-managed project.
  P0 uses two roles of its own, shared by every project on the site:
  - `P0 agent: read`, with `BROWSE_PROJECTS`
  - `P0 agent: write`, with what P0's grantable write tools need:
    `BROWSE_PROJECTS`, `ADD_COMMENTS`, `CREATE_ISSUES`, `EDIT_ISSUES`,
    `TRANSITION_ISSUES`, `EDIT_OWN_COMMENTS`, `WORK_ON_ISSUES`,
    `EDIT_OWN_WORKLOGS`, `LINK_ISSUES`, `CREATE_ATTACHMENTS`,
    `ASSIGN_ISSUES`, `SCHEDULE_ISSUES` and `RESOLVE_ISSUES`. `P0_ROLES` in
    `src/accesses/role/definition.ts` names the tool behind each. It leaves
    out `MOVE_ISSUES`, since its only tool also needs the global Bulk change
    permission, so P0 refuses that tool.

  The connector finds the role by that name, or creates it with a fixed
  description followed by `P0 organization: <tenantId>`. It never adopts a
  role, since every actor of the role gets what P0 grants it. A role with
  P0's name is used only when its description starts with the fixed text and
  names this organization. Otherwise the call fails with `validation_error`
  and asks a Jira admin to rename or delete that role under Settings >
  System > Project roles. Then the connector grants the role each of its
  permissions in the project's permission scheme, where a grant is missing,
  so a scheme that holds an older list gets the rest. Roles and scheme grants
  are never deleted: a grant to a role gives nothing to anyone outside it.

- `{ type: "space", roleId }`, for a team-managed project: one of the
  project's own roles, by the id `install.project.get` reported. It must
  still be one of the project's roles.

Every grant, in a company-managed or a team-managed project, first claims
the site the way `install.site.get` does, before it changes anything. If any
P0 role names another organization, the grant fails with `validation_error`.

The request context's `roleIds` are the role ids P0 recorded at stage, empty
for a company-managed project. The connector adds the account to each role
it keeps with a `POST`, then removes it with a `DELETE` from P0's roles and
from each recorded id, outside the set. P0's roles are found by their fixed
names or by the fixed start of their description, so a renamed one still
counts. A removal goes ahead even when another P0 organization manages the
roles, since it only takes access away. It never sends a `PUT`, because a
`PUT` on a role's actors replaces every member. Adding an account that
already holds a role succeeds, and so does removing one that doesn't.

## `token` access

The user is the request's own token secret, by its bare name, in the project
`vault.projectId` names. No other request reads or deletes it.

- `provisionUser` creates the secret, or reuses it when a retry finds it.
- `setPoliciesForUser` gets the leased pool account, `{ accountId }`. The
  connector reads the pool account's API key from `poolSecret`, whose whole
  value is the key, and writes it as the request's secret's new version.
  Atlassian's MCP server refuses a pool account's OAuth token, so the agent
  uses the key itself. The key read has the same 30-second budget as a Jira
  request, and a read that hasn't finished by then fails with
  `upstream_unavailable`. With no policy, the connector does nothing.
- `deleteUser` deletes the secret. A secret that is already gone counts as
  deleted.

The connector never returns or logs the API key.

## Permissions

The site's admin OAuth client needs these Atlassian scopes:

- `manage:jira-configuration` to add an account to a role
- `manage:jira-project` to remove an account from a role
- `read:jira-user` to find an account by email
- `read:jira-work` to read a project, list its roles, read a role's members
  and read the admin account's own permissions (`install.site.get`)

The same four also cover creating P0's roles and reading and granting in a
permission scheme, checked live on a test site.

P0 requires the admin account to hold the Administer Jira global permission,
and checks it at install with `install.site.get`. Every project role endpoint
accepts a caller with that permission, but Jira also answers 404 to a caller
without it. So when Jira answers a remove with 404, the connector checks
that the admin account still holds Administer Jira. If it does, the project
or role is gone and the account counts as removed. If not, the call fails
with `insufficient_privileges`.

The connector's service account needs these grants in the site's vault
project. P0's installer generates them for each site.

- `roles/secretmanager.secretAccessor` and `roles/secretmanager.viewer` on the
  admin client's secret, and on the pool account secrets, which start with
  `p0_install_jira-ai_<site>_`.
- `secretmanager.secrets.create` on the project, through a custom role.
  Google checks it on the project, so it can't be limited to a prefix.
- `secretmanager.secrets.get`, `secretmanager.secrets.delete` and
  `secretmanager.versions.add` on the token secrets, which start with
  `p0_access-token_jira-ai_<site>_`, through a custom role with a condition
  on that prefix.

The connector reads a secret's latest version and its metadata, which is why
it needs both `secretAccessor` and `viewer` there. It never reads a token
secret back.

## Creating local builds

The image pulls P0's base images from a private GCP Artifact Registry, so log
in and register gcloud as a Docker credential helper for that host first:

```bash
gcloud auth configure-docker us-west1-docker.pkg.dev
```

Then run this from the repository root:

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-jira-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-jira-ai-gcloud:dev .
```

The service needs `INVOKER_SA_EMAIL`, P0's service account: it accepts a
call only with an ID token for that account, and won't start without it.

## Publishing local builds

Fill in the placeholders for your own GCP project/testing environment:

```bash
GCP_PROJECT_ID="your-gcp-project-id"
GCP_REGION="your-gcp-region"
GCP_ARTIFACT_REPOSITORY="your-artifact-registry-repo-name"
```

The `$GCP_ARTIFACT_REPOSITORY` repository must already exist in Artifact
Registry, and you must have permission to push images to it.

```bash
gcloud auth configure-docker "$GCP_REGION-docker.pkg.dev"

docker tag p0-connector-jira-ai-gcloud:dev \
  "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-jira-ai-gcloud:dev"

docker push "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-jira-ai-gcloud:dev"
```

Then deploy a new revision of the Cloud Run service from the pushed image.
