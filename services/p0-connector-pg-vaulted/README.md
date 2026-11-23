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
`{ host, port, database }`: the target, and the database the manager connects to.

The input does not name the manager's secret. The connector is to look it up by `target.host`
in its own environment, in a mapping that Terraform sets, so the P0 control plane cannot point
the connector at another secret or host.

The operation is to run these checks in order, and a failure names its check in `payload.step`
(`PG_VAULTED_INSTALL_STEPS`):

1. `manager_mapping`: the target's host is in the connector's manager mapping.
2. `sign_in`: the manager authenticates to the target.
3. `create_role`: the manager can create roles (`CREATEROLE`).
4. `signal_backend`: the manager can end other logins' sessions (`pg_signal_backend`).
5. `reassign_owned`: the manager can hand a grant login's objects to a grantable role.

Once every check has passed it returns `{ grantableRoles }`.

## Not implemented yet

- `install.validation.get` parses its input and then throws
  `pg-vaulted install.validation.get is not implemented`.
- The connector has no access type: `accesses` is empty.
- The manager mapping has no format yet: neither the environment variable that holds it nor the
  shape of its value is defined.
- The package depends on no PostgreSQL driver and no Secrets Manager client.
- No image is built: the service is not in `.github/workflows/docker.yaml`.
