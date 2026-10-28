# p0-connector-gcp-service-account

GCP service account impersonation connector — mints, and tears down, the
short-lived service account P0 provisions for each agentic session, and
converges which federated principal may impersonate it.

Ships only as a GCP Cloud Run container image.

## What it does

One resource-root access type, `agenticIdentity`. The "user" is a service
account `p0a-<20 hex>@<project>.iam.gserviceaccount.com`; the single "policy"
is a `roles/iam.workloadIdentityUser` binding on that account, naming the
session's workload-identity principal and, optionally, an expiry.

Two properties are worth knowing before reading the code:

- **Every value it writes arrives in the call that writes it.** `createUser`
  is driven by the user body (project, account id, subject); `setPoliciesForUser`
  by the policy (member, expiry). The request context carries only the project
  that id-keyed calls check an address against.
- **Every shape is re-checked here.** Account ids, subjects and members are
  matched against anchored, fixed-length patterns, and a member's pool must sit
  in this service's own organization. A compromised control plane is exactly
  the case this service exists to contain.

The primitives themselves live in `@p0security/gcloud-common`
(`packages/gcloud/src/agentic-identity`); this service is their transport.

## Creating local builds

The build pulls P0's base images from a private Artifact Registry, so log in and
register gcloud as a Docker credential helper for that host first:

```bash
gcloud auth configure-docker us-west1-docker.pkg.dev
```

Then run this from the repository root:

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-gcp-service-account \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-gcp-service-account:dev .
```

## Deploying

The Cloud Run service runs as a dedicated service account holding a custom
role in the identity project with exactly these permissions:

- `iam.serviceAccounts.create`, `.delete`, `.get`
- `iam.serviceAccounts.getIamPolicy`, `.setIamPolicy`
- `resourcemanager.projects.get`

It never holds `iam.serviceAccountKeys.*` or `iam.serviceAccounts.actAs`: tokens
are minted by P0's gateway through the workload-identity binding, not by this
service.
