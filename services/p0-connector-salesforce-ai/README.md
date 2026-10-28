# p0-connector-salesforce-ai

Salesforce (AI) connector - enables access provisioning/deprovisioning for
Salesforce permission sets on API-only agent users.

Each agent gets one API-only Salesforce user, keyed by an agent key that P0
computes. The connector manages that user through the facade in the P0
Salesforce agent package (`/services/apexrest/p0/agents`). The facade touches
only users in the package's agent role and profile, and grants only the
permission sets on the org's grantable list.

- `provisionUser` finds the active agent, or creates or reactivates it.
- `setPoliciesForUser` makes the agent hold exactly the given permission sets.
- `deleteUser` removes every grant and deactivates the user. Salesforce cannot
  delete users. A deactivated user counts as missing, so the next grant
  reactivates it.
- `list` (`type: "permission-set"`) returns the grantable permission sets.

The connector does not mint agent sessions. The P0 gateway exchanges its own
token for a session of the agent user, through the package's token-exchange
handler.

## Consumer secret

The connector logs in as the package's `P0 Provisioner` app with the client
credentials grant. It reads the app's consumer secret from the GCP Secret
Manager secret named by `consumerSecretSecretId`. Its value is the consumer
secret itself.

The connector sends the consumer secret only to a host that ends in
`.my.salesforce.com`.

Ships as a GCP Cloud Run container image.

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
  --build-arg WORKSPACE=@p0security/p0-connector-salesforce-ai \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-salesforce-ai-gcloud:dev .
```

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

docker tag p0-connector-salesforce-ai-gcloud:dev \
  "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-salesforce-ai-gcloud:dev"

docker push "$GCP_REGION-docker.pkg.dev/$GCP_PROJECT_ID/$GCP_ARTIFACT_REPOSITORY/p0-connector-salesforce-ai-gcloud:dev"
```

Then deploy a new revision of the Cloud Run service from the pushed image.
