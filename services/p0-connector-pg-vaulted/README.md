# p0-connector-pg-vaulted

> **Not usable yet.** Install validation is a stub that throws, and the `role` access can't sign in
> to a database yet. See [Not implemented yet](#not-implemented-yet).

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
`{ host, port, database, managerSecret }`: the target, the database the manager connects to,
and the target's manager secret.

The manager secret is in one of two forms:

- A secret P0 names. `managerSecret` is its name, with no ARN:
  `p0/install/postgres/<vpc id>/<target id>/p0manager` (`MANAGER_SECRET_NAME_PATTERN`). The
  `<vpc id>` is `vpc-` and 8 to 17 lowercase hex digits, and the `<target id>` is P0's id of the
  target, `^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`. The customer creates this secret.
- A secret RDS manages. `managerSecret` is its full ARN, in the `aws`, `aws-cn` or `aws-us-gov`
  partition: `arn:<partition>:secretsmanager:<region>:<account>:secret:rds!db-<uuid>-<suffix>`,
  or `rds!cluster-` in place of `rds!db-` (`RDS_MANAGER_SECRET_ARN_PATTERN`). The `<uuid>` is
  lowercase, and the `<suffix>` is the 6 letters and digits Secrets Manager adds.

Anything else is refused: the ARN of any other secret, any other name, and a name without its
`p0manager` leaf. The connector's IAM, which the install's Terraform writes, limits which
secrets the connector can read, so a request can name only a secret the customer gave the
connector.

The operation is to run these checks in order, and a failure names its check in `payload.step`
(`PG_VAULTED_INSTALL_STEPS`):

1. `manager_secret`: the connector reads the manager secret, and its value parses.
2. `sign_in`: the manager authenticates to the target.
3. `create_role`: the manager can create roles (`CREATEROLE`).
4. `signal_backend`: the manager can end other logins' sessions (`pg_signal_backend`).
5. `reassign_owned`: the manager can hand a grant login's objects to a grantable role.

Once every check has passed it returns `{ grantableRoles }`.

### Role access

The `role` access is copied from `p0-connector-pg`, with its IAM sign-in, Cloud SQL support and
`sql` access left out. It runs on the resource-hierarchy perimeter: P0 creates an access role that
can't log in, grants the approved roles to it, then grants it to the user's login. It acts only
on names that start with `p0`, and never on the manager or a role the manager inherits.

`scripts/compare-with-pg.sh` prints how each copied file differs from its original.

## Not implemented yet

- `install.validation.get` parses its input and then throws
  `pg-vaulted install.validation.get is not implemented`.
- The manager can't sign in on RDS. The client throws
  `pg-vaulted manager sign-in is not implemented`, because nothing reads the manager secret yet.
- `createUser` makes a login with no password, as in `p0-connector-pg`. Logins with a password
  kept in Secrets Manager are not built.
- The manager secret's value has no format yet.
- The package depends on no Secrets Manager client.
- No image is built: the service is not in `.github/workflows/docker.yaml`.
