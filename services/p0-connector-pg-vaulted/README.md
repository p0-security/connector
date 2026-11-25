# p0-connector-pg-vaulted

> **Not usable yet.** Install validation is a stub that throws, and the `role` and `sql` accesses
> can't sign in to a database yet. See [Not implemented yet](#not-implemented-yet).

Vaulted PostgreSQL connector, for PostgreSQL on AWS RDS that does not use IAM database
authentication. For each access grant, the connector is to create a PostgreSQL login of the
grant's own and store its password in the customer's AWS Secrets Manager.

It will ship only as an AWS Lambda container image. Each connector belongs to one VPC, whose id
scopes the secrets it can write.

## Terms

- **Target**: one PostgreSQL instance or cluster P0 manages. Its id in P0 is the target id.
- **Manager**: the database login the connector uses for management operations. Its credential
  never reaches P0.
- **Manager secret**: the AWS Secrets Manager secret that holds one target's manager username,
  password and host. The connector only reads it.
- **Grantable role**: a role the manager can grant, so one a grant can be approved for. From
  PostgreSQL 16 that is a role it holds `ADMIN OPTION` on. Before 16, `CREATEROLE` also lets it
  grant any role that is not superuser.
- **Grant key**: 32 lowercase hex digits, derived by P0 from the target and the principal.
- **Grant login**: a login role named `p0v_<grant key>`, shared by one principal's active grants
  on one target.

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

The secret's value is a JSON object with a `username`, a `password` and a `host`. The connector
signs in only when the secret's `host` is the request's host, ignoring case, and its `username`
is the request's manager. A request names the secret and the host separately, so without this
it could send the manager's password to a host the secret is not for. A secret RDS manages
holds no `host`, so it is refused for now. The connector reads the secret in the region its ARN
names, or else in its own region.

The operation is to run these checks in order, and a failure names its check in `payload.step`
(`PG_VAULTED_INSTALL_STEPS`):

1. `manager_secret`: the connector reads the manager secret, and its value parses.
2. `sign_in`: the manager authenticates to the target.
3. `create_role`: the manager can create roles (`CREATEROLE`).
4. `signal_backend`: the manager can end other logins' sessions (`pg_signal_backend`).
5. `reassign_owned`: the manager can hand a grant login's objects to a grantable role.

Once every check has passed it returns `{ grantableRoles }`.

### Role and SQL access

The `role` and `sql` accesses are copied from `p0-connector-pg`, with its IAM sign-in and Cloud
SQL support left out. Both run on the resource-hierarchy perimeter: P0 creates an access role that
can't log in, grants it the approved roles (`role`) or schema and table privileges (`sql`), then
grants it to the user's login. They act only on names that start with `p0`, and never on the
manager or a role the manager inherits.

### Shared login

One grant login serves every active grant of one principal on one target. Each grant still gets
its own access role, so only the login is shared. P0 holds a lock on the login while it
provisions or deletes it, and the connector keeps no state about grants.

- Every request to the `role` and `sql` accesses must carry `grantEndsAt` in its context: the
  latest end among the login's active grants, as an ISO 8601 timestamp with an offset. A request
  without it is refused before the connector connects. A login with no end is never created.
- When the connector finds or creates the login, it sets `LOGIN` and sets `VALID UNTIL` from
  `grantEndsAt`. This applies to `provisionUser` and to `identifyUser`.
  - P0 provisions on each grant, and again when a grant leaves while others remain, so the end
    follows the latest active grant.
  - `LOGIN` is set every time, so a login left `NOLOGIN` by a failed `deleteUser` can sign in
    again.
- P0 calls `deleteUser` only after the last grant leaves. The connector:
  1. Sets the login to `NOLOGIN`.
  2. Ends its open sessions with `pg_terminate_backend`. Install validation checks that the
     manager can do this (`signal_backend`), so `deleteUser` does not check again. If a
     session does not end, the connector still drops the login, then the call fails.
  3. Drops the login.

  `VALID UNTIL` and `REVOKE` act only at the next sign-in or statement, so step 2 is what ends
  access.

## Not implemented yet

- `install.validation.get` parses its input and then throws
  `pg-vaulted install.validation.get is not implemented`.
- The manager can't sign in on RDS. The client throws
  `pg-vaulted manager sign-in is not implemented`, because nothing reads the manager secret yet.
- `createUser` makes a login with no password. The next PR adds the grant secret: the connector
  is to set the login's password and store it in Secrets Manager.
- The manager secret's value has no format yet.
- The package depends on no Secrets Manager client.
- No image is built: the service is not in `.github/workflows/docker.yaml`.
