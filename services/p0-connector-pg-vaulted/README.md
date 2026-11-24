# p0-connector-pg-vaulted

> **Contract only.** This package defines the contract of install validation. The operation is
> a stub that throws, and the connector has no access type yet. See
> [Not implemented yet](#not-implemented-yet).

Vaulted PostgreSQL connector, for PostgreSQL on AWS RDS that does not use IAM database
authentication. For each access grant, the connector is to create a PostgreSQL login of the
grant's own and store its password in the customer's AWS Secrets Manager.

It will ship only as an AWS Lambda container image. Each connector belongs to one VPC, whose id
scopes the secrets it can write.

## Terms

- **Target**: one PostgreSQL instance or cluster P0 manages. Its id in P0 is the target id.
- **Manager**: the database login the connector uses for management operations. Its credential
  never reaches P0.
- **Manager secret**: the AWS Secrets Manager secret that holds one target's manager username
  and password. The connector only reads it.
- **Grantable role**: a role the manager holds `ADMIN OPTION` on, so one a grant can be approved
  for.
- **Grant key**: 32 lowercase hex digits, random, chosen by P0.
- **Grant login**: a login role the connector creates for exactly one grant, named
  `p0v_<grant key>`.

## Contract

The router namespace is `pg-vaulted`. The P0 control plane imports the contract from
`@p0security/p0-connector-pg-vaulted/connector`, which loads no handler.

### Install validation

`pg-vaulted.install.validation.get` takes `{ target }` and is to write nothing. The target is
`{ host, port, database, managerSecretArn }`: the target, the database the manager connects to,
and the full ARN of the target's manager secret.

The P0 control plane names the manager secret, as it names the private key secret of the
Snowflake (AI) and GitHub (AI) connectors. The connector's IAM, which the install's Terraform
writes, limits which secrets the connector can read, so a request can name only a secret the
customer gave the connector. `managerSecretArn` must be a full Secrets Manager ARN in the `aws`,
`aws-cn` or `aws-us-gov` partition, and a secret's name alone is refused. An ARN whose secret
name starts with `p0/postgres-ai/` is refused too: that is where grant secrets live, which the
connector writes and never reads.

The operation is to run these checks in order, and a failure names its check in `payload.step`
(`PG_VAULTED_INSTALL_STEPS`):

1. `manager_secret`: the connector reads the manager secret, and its value parses.
2. `sign_in`: the manager authenticates to the target.
3. `create_role`: the manager can create roles (`CREATEROLE`).
4. `signal_backend`: the manager can end other logins' sessions (`pg_signal_backend`).
5. `reassign_owned`: the manager can hand a grant login's objects to a grantable role.

Once every check has passed it returns `{ grantableRoles }`.

## Not implemented yet

- `install.validation.get` parses its input and then throws
  `pg-vaulted install.validation.get is not implemented`.
- The connector has no access type: `accesses` is empty.
- The manager secret's value has no format yet.
- The package depends on no PostgreSQL driver and no Secrets Manager client.
- No image is built: the service is not in `.github/workflows/docker.yaml`.
