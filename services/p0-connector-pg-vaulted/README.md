# p0-connector-pg-vaulted

> **Scaffold only.** The service builds, bundles and serves its version under `metadata`. It
> has no access router and no install validation. See
> [Not implemented yet](#not-implemented-yet).

Vaulted PostgreSQL connector, for PostgreSQL on AWS RDS that does not use IAM database
authentication. For each access grant, the connector is to create a PostgreSQL login of the
grant's own and store its password in the customer's AWS Secrets Manager.

It will ship only as an AWS Lambda container image. Each connector belongs to one VPC, whose id
scopes the secrets it can write.

## Not implemented yet

- The router serves `metadata.get` and nothing else: `accesses` and `install` are empty.
- The package depends on no PostgreSQL driver and no Secrets Manager client.
- No image is built: the service is not in `.github/workflows/docker.yaml`.
