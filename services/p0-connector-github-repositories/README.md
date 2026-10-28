# p0-connector-github-repositories

GitHub Repositories connector: grants an org member a direct collaborator role
on one repository, just in time, and restores their prior direct role when the
grant ends.

Ships as an AWS Lambda container image. Each customer runs one connector per
GitHub org.

## What it does

One resource-root access, `role`. The user is the org member's login, which
is both the user body and the user id. The policy is `{ repo, role }`: the
repository's bare name, and the direct role to leave the user with on it, in
the form GitHub's collaborator `PUT` accepts (`pull`, `triage`, `triage_plus`,
`push`, `maintain`, `admin`, or a custom role's name), or `null` for no direct
role. The org and the user's GitHub user id, `githubUserId`, ride in the
request context.

Five properties are worth knowing before reading the code:

- **P0 holds no GitHub credential.** The connector acts as a GitHub App the
  customer created, owns and installed on their org. It reads the app's private
  key from the customer's own AWS Secrets Manager, through a pointer P0 sends
  with each call. Repository Administration: write amounts to repo admin, so that
  key never leaves the customer's cloud.
- **Every call mints its own installation token**, asking for the least it
  needs. Changing a role gets one repository with `administration: write`, and
  so does the invitation sequence (listing the repo's invitations and
  cancelling the app's), which shares one token from start to finish. Reading
  a role gets one repository with `metadata: read`. Looking up an account
  needs no permission, since GitHub's user endpoints are public, but a token
  has to ask for one, so it uses `metadata: read` on every repository in the
  installation's selection. Listing repositories gets
  `metadata: read` on every repository in the selection too, and so does
  looking up a repository's id, which may be given a renamed repository's old
  name, and GitHub won't scope a token by that. An org read gets
  one org permission (`members: read` or `organization_custom_roles: read`)
  and names no repositories, which GitHub reads as every repository in the
  selection, so those tokens also carry `metadata: read` on all of them. The
  installation is looked up from the org each time, never stored.
- **Only `setPoliciesForUser` changes anything in GitHub.** Everything else
  reads, or doesn't call GitHub at all.
- **Only direct roles count, only org members get one, and nobody is ever
  invited.** Team and base permission access is never read as the user's role
  or changed. Setting a role checks that the user is an active org member
  before the `PUT`, and refuses anyone else, outside collaborators included,
  without calling it. Removing the direct role works for anyone.

  If GitHub still answers a `PUT` with an invitation (the user left the org
  between the check and the `PUT`), the connector cancels it and the call
  fails. If the cancel fails, the error says an invitation may be pending. P0
  retries the grant, and the retry, finding the user isn't a member, cancels
  any invitation the app sent them before it refuses, so the pending-invitation
  error is what's left only when every attempt failed to cancel. Removing a
  non-member's direct role also cancels the app's invitations to them, which
  covers P0's rollback of such a grant, and fails the same way when it can't.
  Invitations
  come from the app's `<slug>[bot]` user, with the slug read from `GET /app`.
  An invitation an admin sent is never touched.

  A `PUT` GitHub answers without an invitation doesn't prove membership
  either: an existing outside collaborator who left the org between the check
  and the `PUT` gets the role outright. So setting a role checks membership
  again after it, and if the user has left, removes their direct role, cancels
  the app's invitations to them, and fails.

  Without an invitation GitHub just reported, a failure before the search of
  the repo's invitations starts (minting its token, or reading the slug) isn't
  a sign one is pending. It fails the call with its own reason instead, such as
  a missing `administration: write`, a suspended installation or rejected
  credentials.

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
`repo` and the name it has now, `[]` or one item; a renamed repository's old
name finds it too).

Install validation (`install.validation.get`) reports whether GitHub accepts
the key, whether the app is installed on the org, whether that installation is
suspended, which of the four required permissions it lacks, and its repository
selection.

## The customer app's permissions

- Repository: Administration (read and write), Metadata (read)
- Organization: Members (read), Custom repository roles (read)

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
  -f ./docker/connector/lambda/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-github-repositories \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-github-repositories:dev .
```

This will set your locally-built image to have the tag `dev`. To publish it to
your own ECR, follow the same steps as in
[`p0-connector-github`](../p0-connector-github/README.md#aws-ecr).

## Deploying

The connector's identity must be able to read exactly one secret, the app's
private key, and nothing else. This is a hard requirement: P0 sends the secret
name with each call, so any other secret the identity can read is one a
request could point it at. Grant on that one secret resource only: never a
wildcard that could match another secret, and never a grant at the account
level.

The Lambda's execution role needs `secretsmanager:GetSecretValue` on the
secret's full ARN (or its name followed by `-??????`, which matches only that
secret's random suffix). If the secret is encrypted with a customer-managed KMS
key, the role also needs `kms:Decrypt` on that key, scoped with
`kms:ViaService = secretsmanager.<region>.amazonaws.com`. The default
`aws/secretsmanager` key needs no grant.

It needs to reach `api.github.com`, and doesn't need a VPC.
