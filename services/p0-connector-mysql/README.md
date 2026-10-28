# p0-connector-mysql

MySQL connector - enables access provisioning/deprovisioning directly
within a P0-managed MySQL instance.

Ships only as an AWS Lambda container image. If you are installing a connector
for MySQL via CloudSQL, follow services/p0-connector-cloudsql/README.md instead.

## Creating local builds

The build pulls P0's base images from a private GCP Artifact Registry, so log in and register
gcloud as a Docker credential helper for that host first. This is required even though the
connector itself deploys to AWS:

```bash
gcloud auth configure-docker us-west1-docker.pkg.dev
```

Then run this from the repository root:

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/lambda/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-mysql \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-mysql:dev .
```

This will set your locally-built images to have the tag `dev`.

## Publishing local builds to AWS (ECR)

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

docker tag p0-connector-mysql:dev \
  "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$AWS_ECR_REPOSITORY:dev"

docker push "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$AWS_ECR_REPOSITORY:dev"
```

## Deploying new connector image

If you already have a Lambda function set up (e.g. from installing MySQL in P0),
go to the AWS Console and deploy the function from the newly pushed image.
