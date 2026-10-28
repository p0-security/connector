# p0-connector-github

GitHub connector: grants an org member a direct collaborator role on one
repository, membership of one team, or a place on one branch's list of who can
merge without its required reviews, just in time, and restores what they had
before when the grant ends.

Ships as both an AWS Lambda container image and a GCP Cloud Run container
image, built from the same workspace with two different Dockerfiles. Each
customer runs one connector per GitHub org.

## What it does

Three resource-root accesses, `role`, `team` and `force-merge`. In all three,
the user is the org member's login, which is both the user body and the user
id, and the org and the user's GitHub user id, `githubUserId`, ride in the
request context.

The `team` access is covered in [The `team` access](#the-team-access), and
`force-merge` in [The `force-merge` access](#the-force-merge-access). The rest
of this section describes `role`, whose policy is `{ repo, role }`: the
repository's bare name, and the direct role to leave the user with on it, in
the form GitHub's collaborator `PUT` accepts (`pull`, `triage`, `triage_plus`,
`push`, `maintain`, `admin`, or a custom role's name), or `null` for no direct
role.

Five properties shape the code:

- **P0 holds no GitHub credential.** The connector acts as a GitHub App the
  customer created, owns and installed on their org. It reads the app's private
  key from the customer's own secret manager, AWS Secrets Manager or Google
  Secret Manager, through a pointer P0 sends with each call. Repository
  Administration: write amounts to repo admin, and Members: write can change
  anyone's teams and their role in the org, so that key never leaves the
  customer's cloud.
- **Every call mints its own installation token**, asking for the least it
  needs. Changing a role gets one repository with `administration: write`.
  Reading a role gets one repository with `metadata: read`. Looking up an account
  needs no permission, since GitHub's user endpoints are public, but a token
  has to ask for one, so it uses `metadata: read` on every repository in the
  installation's selection. Listing repositories gets
  `metadata: read` on every repository in the selection too, and so does
  looking up a repository's id, which may be given a renamed repository's old
  name, and GitHub won't scope a token by that. An org read gets
  one org permission (`members: read` or `organization_custom_roles: read`)
  and names no repositories, which GitHub reads as every repository in the
  selection, so those tokens also carry `metadata: read` on all of them.
  Changing a team membership gets `members: write`, which names no
  repositories either. The installation is looked up from the org each time,
  never stored.
- **Only `setPoliciesForUser` changes anything in GitHub.** Everything else
  reads, or doesn't call GitHub at all.
- **Only direct roles count, only org members get one, and nobody is ever
  invited.** Team and base permission access is never read as the user's role,
  and a role grant never changes it (team membership is the `team` access's).
  Setting a role checks that the user is an active org member before the
  `PUT`, and refuses anyone else, outside collaborators included, without
  calling it. Removing the direct role works for anyone.

  If GitHub still answers a `PUT` with an invitation (the user left the org
  between the check and the `PUT`), the call fails as `invitation_pending`,
  and the error asks the admin to cancel the invitation in the repo's
  collaborator settings. The connector makes no invitation call of its own.

  A `PUT` GitHub answers without an invitation doesn't prove membership
  either: an existing outside collaborator who left the org between the check
  and the `PUT` gets the role outright. So setting a role checks membership
  again after it, and if the user has left, removes their direct role and
  fails.

- **A user is an account, not a login.** A login can be renamed, and the role
  moves with the account, so the old login can end up naming someone else. P0
  captures the GitHub user id at request time (the `account` listing).
  `getUser` looks it up (`GET /user/{id}`) and returns the login the account
  has now, and that is the user id every policy change acts on. GitHub answers
  404 for a deleted account, and also for some that still exist, such as a
  spam-flagged one, and `getUser` returns `null` for both. A grant then fails
  in `createUser` with `user_not_found`. A revoke changes nothing and
  succeeds, since an account GitHub doesn't show is taken to hold no role.

A grant and a revoke are both `setPoliciesForUser` with exactly one policy,
and the connector doesn't tell them apart. A grant sends the requested role. A
revoke sends the role the user had before the grant, which P0 read when it
staged the request, or `null` when they had none. The connector sets that role
without reading the one there first, so a change someone made by hand during
the grant is overwritten, not reported. Running either again changes nothing
more.

When the prior role can't go back, because the user isn't an org member any
more or the role is now below the org's base permission, the connector
refuses it as it would a grant. P0 then revokes with `null` instead, which
removes the direct role.

`list` gets no request context, so every query is
`{ type, context: { org, appId, privateKey } }`, with a lookup's own fields
beside `context`. It answers six: `repository` (the installation's
repository selection, keyed by bare name), `role` (built-in roles, plus custom
roles on Enterprise Cloud), `direct-role` (one user's direct role on one repo,
`[]` or one item, given `repo` and `login`), `member` (the login of the member
with a given verified-domain `email`), `account` (the GitHub user id behind
a given `login`, `[]` or one item) and `repository-id` (the id behind a given
`repo` and the name it has now, `[]` or one item, which a renamed
repository's old name finds too).

Install validation (`install.validation.get`) reports whether GitHub accepts
the key, whether the app is installed on the org, whether that installation is
suspended, which of the four required permissions it lacks, and its repository
selection.

## The `team` access

The policy is `{ teamId, role }`: the team's GitHub id, and the membership to
leave the user with on it, `member` or `maintainer`, or `null` for none. Like
a role, a grant and a revoke are both `setPoliciesForUser` with exactly one
policy. A grant sends the requested membership. A revoke sends the membership
the user had before the grant, which P0 read when it staged the request, or
`null` when they weren't on the team. The connector sets it without reading
the one there first.

What holds for a role holds for a membership, with these differences:

- **A team is an id, not a slug.** A team's maintainers can rename it, which
  changes its slug, and another team can then take the old one. A `maintainer`
  grant would let its holder move the team out from under their own revoke.
  So a requestor names a team by its slug, P0 captures the team's id at
  request time (the `team-id` lookup), and every change and membership read
  goes through GitHub's by-id routes
  (`/organizations/{org_id}/team/{team_id}/...`), or, in GraphQL, the team's
  node id. The slug the team has now is looked up for messages only. Ids
  aren't reused, so a team that's gone was deleted, and its members went with
  it: setting a membership of it fails with `object_not_found`, and `null`
  succeeds, since there's nothing to remove.
- **Only the team's own members count.** GitHub's REST API counts a child
  team's members as the parent's. `team-membership` reads the user's own
  membership of the team, so membership of a child team is never recorded as
  the prior membership, and a revoke doesn't leave the user on the parent.
  For someone GitHub counts as a member, that means walking the team's own
  members page by page.
- **Only org members get a membership.** GitHub answers a membership `PUT` for
  someone outside the org by inviting them to it, with the team attached, and
  reports the membership as pending. Setting a membership checks that the user
  is an active org member before the `PUT`, and refuses anyone else without
  calling it. If GitHub still leaves the membership pending (the user left
  the org between the check and the `PUT`), the connector removes the
  membership and the call fails as `not_org_member`, or as
  `membership_pending` when the removal fails. The connector never reads or
  cancels the org's invitations.
- **GitHub can refuse the change.** It answers a change to a team that's
  synced with an identity provider group with a 403, without documenting its
  wording. A 403 on the change that isn't a missing permission, a suspended
  installation, a rate limit or the org's IP allow list is reported as
  `team_change_refused`, quoting GitHub and naming the sync as the usual
  cause.

Removing a membership the user doesn't have succeeds.

A revoke restores the user's own membership of the team, and nothing else. A
`maintainer` can add other org members to the team, promote them to
maintainer, and nest a team they also maintain under it, whose members then
inherit the team's access. None of that is undone when the grant ends, so a
`maintainer` grant is only as safe as trusting its holder with those changes.

Its `list` answers five queries: `team` (the org's teams, keyed by slug),
`team-id` (the id behind a given `team` slug, `[]` or one item),
`team-membership` (one user's own membership of one team, `[]` or one item,
given `teamId` and `login`), and the `member` and `account` lookups it shares
with `role`.

## The `force-merge` access

The policy is `{ repo, branch, allowed }`: a repository's bare name, one of
its branches, and whether the user is on the branch's bypass list, the users,
teams and apps that can merge without the pull request reviews the branch's
protection requires. A grant sends `true`. A revoke sends what P0 read with
the `bypass-allowance` lookup when it staged the request, so `false` unless
the user was already on the list.

- **Only a branch with a rule of its own.** GitHub applies a protection rule
  whose pattern is the branch's exact name ahead of any wildcard rule that
  also matches it, so that's the rule a change edits. A branch protected by a
  wildcard rule only is refused with `wildcard_rule`, since its bypass list
  would cover every branch the pattern matches. The rules' patterns come from
  GraphQL (`branchProtectionRules`), since REST shows a branch's protection
  but not which rule it comes from. A branch with no protection is refused
  with `branch_not_protected`, and one whose protection doesn't require pull
  request reviews with `reviews_not_required`.
- **The list is read, changed and written back whole.** GitHub's
  `PATCH .../protection/required_pull_request_reviews` replaces each list it's
  sent, so the connector reads the protection
  (`GET /repos/{owner}/{repo}/branches/{branch}/protection`), adds or removes
  the login, and sends the users, teams and apps back together, with nothing
  else, so the branch's other review settings stay. It then reads the list
  back, and writes again if someone else's change landed in between and
  dropped it, up to three times before failing with `change_not_kept`.
- **Org members only.** A grant checks that the user is an active org member
  first, like the other accesses. A change to the list never invites anyone.
- **GitHub can refuse the change.** It answers 422 for a user without write
  access to the repository, and for a list over its limit of 100 users, teams
  and apps in all. That's reported as `bypass_change_refused`, quoting
  GitHub.

A revoke works for anyone. It succeeds without a change when the branch has
no rule of its own or no required reviews any more, since the list P0 added to
went with them. A branch that's gone while its rule is still there fails with
`rule_outlived_branch`: REST can't change a rule's list without its branch.

Reads take `administration: read` on the one repository, and a change
`administration: write`, like a role change.

Its `list` answers four queries: `bypass-allowance` (whether one user is on
one branch's list, `[]` or one item, given `repo`, `branch` and `login`),
`protected-branch` (the branches of one `repo` with a rule of their own,
keyed by name), and the `member` and `account` lookups it shares with `role`.

## The customer app's permissions

- Repository: Administration (read and write), Metadata (read)
- Organization: Members (read and write), Custom repository roles (read)

Members needs write for the `team` access only. An app that was created with
Members (read) still gives repository roles, but install validation reports
`members=write` as missing until the app's permission is raised and the
update accepted on the installation.

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
  --build-arg WORKSPACE=@p0security/p0-connector-github \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-github:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-github \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-github-gcloud:dev .
```

These commands tag your local builds `dev`. To publish them to your own ECR
or Artifact Registry, follow the same steps as in
[`p0-connector-github-ai`](../p0-connector-github-ai/README.md#publishing-local-builds).

## Deploying

The connector's identity must be able to read exactly one secret, the app's
private key, and nothing else. This is a hard requirement: P0 sends the secret
name with each call, so any other secret the identity can read is one a
request could point it at. Grant on that one secret resource only: never a
wildcard that could match another secret, and never a grant at the account or
project level.

- **AWS**: the Lambda's execution role needs `secretsmanager:GetSecretValue` on
  the secret's full ARN (or its name followed by `-??????`, which matches only
  that secret's random suffix). If the secret is encrypted with a
  customer-managed KMS key, the role also needs `kms:Decrypt` on that key,
  scoped with `kms:ViaService = secretsmanager.<region>.amazonaws.com`. The
  default `aws/secretsmanager` key needs no grant.
- **GCP**: the connector reads the secret's value with
  `secretmanager.versions.access` and then its version metadata with
  `secretmanager.versions.get`, so its service account needs both on that
  secret. `roles/secretmanager.secretAccessor` covers only the first. Bind it
  together with `roles/secretmanager.viewer` on the secret resource (not the
  project), or bind one custom role holding just those two permissions on the
  secret.

On Cloud Run, P0 calls the service with an identity token for its own service
account, which needs `roles/run.invoker` on the service, and `roles/run.viewer`
so P0 can look up the service's URL. The Terraform and script that P0's
installer generates set `INVOKER_SA_EMAIL` to that service account: the
connector refuses every caller whose token isn't for it, on top of Cloud Run's
own check.

It needs to reach `api.github.com`, and doesn't need a VPC.
