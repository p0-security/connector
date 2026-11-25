# p0-connector-pg-vaulted

Vaulted PostgreSQL connector, for PostgreSQL on AWS RDS that does not use IAM database
authentication. The connector signs in to each target as its manager, with a username and
password it reads from the target's manager secret in the customer's AWS Secrets Manager. For
each access grant, it is to create a PostgreSQL login of the grant's own and store its password
in Secrets Manager. That part is not built yet: see [Not implemented yet](#not-implemented-yet).

It ships only as an AWS Lambda container image. Each connector belongs to one VPC, whose id
scopes the secrets it can read.

## Terms

- **Target**: one PostgreSQL instance or cluster P0 manages. Its id in P0 is the target id.
- **Manager**: the database login the connector uses for management operations. Its credential
  never reaches P0.
- **Manager secret**: the AWS Secrets Manager secret that holds one target's manager username
  and password. The connector only reads it.
- **Grantable role**: a role a grant can be approved for. See
  [Grantable roles](#grantable-roles).
- **Grant key**: 32 lowercase hex digits, random, chosen by P0.
- **Grant login**: a login role the connector is to create for exactly one grant, named
  `p0v_<grant key>`.

## Contract

The router namespace is `pg-vaulted`. The P0 control plane imports the contract from
`@p0security/p0-connector-pg-vaulted/connector`, which loads no handler, database driver or
Secrets Manager client.

### The manager secret

A request names its target's manager secret as `managerSecret`, in one of two forms:

- A secret P0 names. `managerSecret` is its name, with no ARN:
  `p0/install/postgres/<vpc id>/<target id>/p0manager` (`MANAGER_SECRET_NAME_PATTERN`). The
  `<vpc id>` is `vpc-` and 8 to 17 lowercase hex digits, and the `<target id>` is P0's id of the
  target, `^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`. The customer creates this secret.
- A secret RDS manages. `managerSecret` is its full ARN, in the `aws`, `aws-cn` or `aws-us-gov`
  partition: `arn:<partition>:secretsmanager:<region>:<account>:secret:rds!db-<uuid>-<suffix>`,
  or `rds!cluster-` in place of `rds!db-` (`RDS_MANAGER_SECRET_ARN_PATTERN`). The `<uuid>` is
  lowercase, and the `<suffix>` is the 6 letters and digits Secrets Manager adds.

Anything else is refused before the connector calls Secrets Manager: the ARN of any other
secret, any other name, and a name without its `p0manager` leaf. The connector's IAM, which the
install's Terraform writes, limits which secrets the connector can read, so a request can name
only a secret the customer gave the connector. See [IAM](#iam).

### Install validation

`pg-vaulted.install.validation.get` takes `{ target }`. The target is
`{ host, port, database, managerSecret }`: the target's address, the database the manager
connects to, and the target's manager secret. It runs these checks in order and stops at the
first that fails (`PG_VAULTED_INSTALL_STEPS`):

1. `manager_secret`: the connector reads the manager secret, in the region
   [Reading the manager secret](#reading-the-manager-secret) names, and its value parses.
2. `sign_in`: the manager authenticates to the target and runs `SELECT 1`.
3. `create_role`: the manager can create roles. It has `CREATEROLE` or is superuser.
4. `signal_backend`: the manager can end other logins' sessions. It has the privileges of
   `pg_signal_backend` or is superuser.
5. `reassign_owned`: the manager can hand a grant login's objects to a grantable role. The
   connector creates a probe role named like a grant login, runs the statements under
   [What the connector grants itself](#what-the-connector-grants-itself) to reassign what the
   probe role owns to the first grantable role, and rolls the transaction back. With no
   grantable role, the check passes once the probe role is created.

Once every check has passed it returns `{ grantableRoles }`. It leaves nothing behind: the
transaction of `reassign_owned` holds its only writes, and is always rolled back.

A failed check is a `ConnectorError` whose payload has the check in `step` and the target's
host in `host`. A failure that PostgreSQL reported also has its SQLSTATE in `sqlState`, and a
network or TLS failure has the error's code in `code`. No message quotes the server's message
or a statement. The error's type is one of these:

| Type                      | When                                                                                                                                           |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `validation_error`        | The manager secret's value does not parse, or the manager secret is one P0 names and the connector's `AWS_REGION` is not set.                  |
| `object_not_found`        | The manager secret does not exist, the target's database does not, or a role a statement names does not.                                       |
| `insufficient_privileges` | The connector's role may not read the manager secret, PostgreSQL refuses the manager's sign-in, or the manager lacks a privilege.              |
| `upstream_unavailable`    | The connector cannot reach Secrets Manager or PostgreSQL, the server's certificate is not one AWS signed, or PostgreSQL cancelled a statement. |
| `unknown`                 | PostgreSQL reported a failure the connector does not map.                                                                                      |

`src/postgres/errors.ts` maps SQLSTATEs to these types.

### Role and SQL access

The `role` and `sql` accesses are copied from `p0-connector-pg`, with its IAM sign-in and Cloud
SQL support left out. Both run on the resource-hierarchy perimeter: P0 creates an access role that
can't log in, grants it the approved roles (`role`) or schema and table privileges (`sql`), then
grants it to the user's login. They act only on names that start with `p0`, and never on the
manager, the session's user or a role the manager inherits.

The request context's `db` is `{ host, port, database, managerSecret, targetId, cloud }`.
`managerSecret` takes the same forms as install validation's, and `targetId` is P0's id of the
target. A manager secret P0 names must have `targetId` as its `<target id>`, or the request is
refused before the connector signs in. A secret RDS manages names no target, so nothing ties it
to one. The context has no VPC id, so nothing compares the secret's `<vpc id>` with anything.

`list` with `type: "role"` lists the grantable roles, and a `role` policy may grant only one of
them.

## Manager

### Reading the manager secret

The connector reads the request's manager secret on each call that signs in:

- A secret P0 names is read in the connector's own region: the `AWS_REGION` that Lambda sets.
  When `AWS_REGION` is not set, the call fails with `validation_error` and reads nothing.
- A secret RDS manages is read in the region its ARN names, which must be reachable from the
  connector's VPC. From a VPC with no NAT, only the region of its Secrets Manager interface
  endpoint is reachable, since an endpoint's private DNS covers only its own region.

The P0 control plane chooses the secret. One connector serves every target in its VPC, and
keeps no list of targets of its own.

Nothing ties the manager secret to `host`. A request that pairs one target's host with another
target's manager secret signs in to that host with the other target's credential, which the
host refuses unless both targets share the login. What limits such a request:

- TLS is verified against the AWS RDS certificate authorities, so the connector signs in only to
  a server with a certificate AWS issued.
- The connector's security group reaches only its VPC's databases and the Secrets Manager
  endpoint.
- A secret P0 names must have the request's `targetId` as its `<target id>`. A secret RDS
  manages has no such check.

### The secret's value

The manager secret's value is JSON with `username` and `password`, both non-empty strings. AWS
writes this shape for a secret that RDS manages, and the customer writes it to a secret P0
names. The connector ignores every other key, `host` and `port` included: the target comes from
the request.

```json
{ "username": "p0_manager", "password": "..." }
```

The connector never logs the value, and no error it throws holds the value or the Secrets
Manager error it came with.

### Connection

The connector opens a client per call, as the manager, to the request's database, and closes it
when the call ends.

- TLS is always on. The connector verifies the server's certificate against the AWS RDS
  certificate authorities (`aws-ssl-profiles`). No request field and no environment variable
  turns TLS off.
- A connection that is not made within `DB_CONNECTION_TIMEOUT` milliseconds, 10 seconds unless
  set, fails.

### Grantable roles

`list` with `type: "role"`, the `role` policy's check, and install validation's
`grantableRoles` come from one query (`GRANTABLE_ROLES_SQL` in `src/postgres/catalog.ts`). A
role is grantable when all of these hold:

- It cannot log in.
- It is not superuser.
- Its name does not start with `pg_`, `rds`, `p0` or `P0`.
- Its name is one a policy can hold: ASCII letters, digits and `. _ @ + -`, at most 63 bytes.
- The manager holds `ADMIN OPTION` on it:
  - From PostgreSQL 16, the manager holds `ADMIN OPTION` on the role, or inherits the
    privileges of a role that does.
  - Before PostgreSQL 16, the manager holds `ADMIN OPTION` on the role, or is a member of a
    role that does. PostgreSQL itself would let a login with `CREATEROLE` grant every role
    that is not superuser. The connector does not offer those roles, so the customer chooses
    the grantable roles the same way on every version. This is a limit the connector keeps,
    not one PostgreSQL enforces before 16.
  - A superuser manager can grant every such role.

### Manager privileges

The manager does not need to be superuser. These statements, run by a superuser, set up a
manager that passes install validation:

```sql
CREATE ROLE p0_manager LOGIN PASSWORD '...' CREATEROLE;
GRANT pg_signal_backend TO p0_manager;
-- once for each role a grant may be approved for
GRANT analyst TO p0_manager WITH ADMIN OPTION;
```

What each version needs, as measured on PostgreSQL 14.25, 16.16 and 17.12. The connector treats
every version before 16 as 14, and every later version as 16.

| The manager needs                    | PostgreSQL 14                                                                                                   | PostgreSQL 16 and 17                                                                                                                                |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CREATEROLE`                         | Required.                                                                                                       | Required.                                                                                                                                           |
| `pg_signal_backend`                  | Required.                                                                                                       | Required, and not `WITH INHERIT FALSE`: a membership the manager does not inherit cannot signal a backend.                                          |
| The `INHERIT` attribute, the default | Required. A `NOINHERIT` manager can use neither `pg_signal_backend` nor the privileges `REASSIGN OWNED` needs.  | Not required, but a grant to a `NOINHERIT` manager is `INHERIT FALSE` unless it says `WITH INHERIT TRUE`, and `pg_signal_backend` needs it.         |
| `ADMIN OPTION` on each approved role | Required by the connector, which offers no other role. PostgreSQL itself would let `CREATEROLE` grant the role. | Required. `WITH ADMIN OPTION, INHERIT FALSE, SET FALSE` is enough: the manager can then hand out the role, and holds none of the role's privileges. |

#### What the connector grants itself

`REASSIGN OWNED BY <grant login> TO <owner>` needs more than the grants above, so the manager
grants itself the rest first (`reassignOwnedStatements` in `src/postgres/catalog.ts`). Install
validation is the only caller so far. It runs the statements on its probe role, in the
transaction it rolls back.

| Statement                         | PostgreSQL 14                                    | PostgreSQL 16 and 17                                      |
| --------------------------------- | ------------------------------------------------ | --------------------------------------------------------- |
| Take the grant login's privileges | `GRANT "<grant login>" TO current_user`          | `GRANT "<grant login>" TO current_user WITH INHERIT TRUE` |
| Take the right to hand to `owner` | `GRANT "<owner>" TO current_user`                | `GRANT "<owner>" TO current_user WITH SET TRUE`           |
| Reassign                          | `REASSIGN OWNED BY "<grant login>" TO "<owner>"` | `REASSIGN OWNED BY "<grant login>" TO "<owner>"`          |

Each grant is there because a measured setup fails without it. Each setup ran as the manager,
between `BEGIN` and `ROLLBACK`, on the `postgres:14`, `postgres:16` and `postgres:17` Docker
images. In every row the manager has `CREATEROLE` and has just created the probe role with
`CREATE ROLE "p0v_<32 hex digits>" NOLOGIN`:

| Setup                                                                             | PostgreSQL 14                                                               | PostgreSQL 16 and 17                                                                     |
| --------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| No grant of the probe role to the manager                                         | `permission denied to reassign objects`                                     | `permission denied to reassign objects`                                                  |
| `GRANT <probe> TO current_user`                                                   | Passes.                                                                     | Passes, but fails as above for a `NOINHERIT` manager.                                    |
| `GRANT <probe> TO current_user WITH INHERIT TRUE`                                 | Syntax error.                                                               | Passes, for a `NOINHERIT` manager too. `SET FALSE` does not matter.                      |
| `GRANT <probe> TO current_user WITH INHERIT FALSE, SET TRUE`                      | Syntax error.                                                               | `permission denied to reassign objects`                                                  |
| The manager holds no `ADMIN OPTION` on `owner`                                    | The role is not grantable.                                                  | The role is not grantable.                                                               |
| `owner` was granted to the manager `WITH ADMIN OPTION`                            | Passes.                                                                     | Passes.                                                                                  |
| `owner` was granted `WITH ADMIN OPTION, SET FALSE`, with or without `INHERIT`     | Syntax error.                                                               | `must be able to SET ROLE "<owner>"`. Passes after the grant of `owner` `WITH SET TRUE`. |
| `ADMIN OPTION` on `owner` only through a `NOINHERIT` role the manager is in       | `permission denied to reassign objects`. Passes after the grant of `owner`. | Not applicable: inheritance is set on each grant.                                        |
| `ADMIN OPTION` on `owner` only through a grant the manager does not inherit       | Not applicable: no grant sets inheritance.                                  | `permission denied to grant role "<owner>"`, so the role is not grantable.               |
| The login owns a table. The manager reassigns, then `DROP OWNED` and `DROP ROLE`. | The table's owner is `owner`, and the login is gone.                        | The table's owner is `owner`, and the login is gone.                                     |

With these grants, a manager that passes `create_role` and `signal_backend` has passed
`reassign_owned` on every setup measured. The check stays because it runs the real statements
on the real target, which no catalog query stands in for.

## IAM

The connector's execution role needs `secretsmanager:GetSecretValue` on
`arn:<partition>:secretsmanager:<region>:<account>:secret:p0/install/postgres/<vpc id>/*`, plus
the ARN of each RDS-managed manager secret that the VPC's targets use, and on no other secret.
The `*` covers the suffix Secrets Manager adds to each secret's name. A manager secret that a
customer-managed KMS key encrypts also needs `kms:Decrypt` on that key.

A manager secret must be in the connector's account. A secret in another account is readable only
with a resource policy on the secret that lets the connector's role read it, and only when a
customer-managed KMS key encrypts it, since `aws/secretsmanager` cannot be used from another
account.

## Tests

The unit tests run with the repository's `yarn :test`. Install validation and the client take
their Secrets Manager client, `AWS_REGION` and knex as `dependencies`, which the tests fill with
fakes. The fake database answers a catalog query by the identity of its SQL constant, so it runs
none of the SQL.

Two kinds of test run the SQL against PostgreSQL. CI runs both in
`.github/workflows/test-pg-vaulted-integration.yaml`, on a pull request that changes this
service, `connector-core` or `secret-manager-client`:

- The integration tests (`src/**/*.integration.test.ts`) run install validation and the
  grantable-role list against PostgreSQL 14 and 16 in Docker, as a manager that is not
  superuser. They reach the servers without TLS through a `knex` dependency that turns it off,
  which no request can.
- The `role` and `sql` suites (`src/__tests__/role.test.ts` and `sql.test.ts`) run the accesses
  as the superuser `pspladmin`, password `psqlpass`, and the boundary tests as a manager that
  is not superuser. They skip when `CI` is set, so CI runs them with it unset, on PostgreSQL 16
  only: the `sql` suite's injection checks assume no role has `CREATE` on the `public` schema,
  which every role has before PostgreSQL 15.

To run them yourself, from this directory:

```sh
./scripts/integration-db.sh up
yarn test:integration
env -u CI PG_PORT=54316 yarn vitest run src/__tests__/role.test.ts src/__tests__/sql.test.ts
./scripts/integration-db.sh down
```

`integration-db.sh up` starts one server per version on `127.0.0.1`, at ports 54314 and 54316,
with the superuser the `role` and `sql` suites expect. Without `PG_PORT` those suites use
port 5432.

## Not implemented yet

- `createUser` makes a login with no password, as in `p0-connector-pg`. Logins with a password
  kept in Secrets Manager are not built, and the connector writes no secret.
- Nothing yet runs the statements under
  [What the connector grants itself](#what-the-connector-grants-itself) outside install
  validation's rolled-back transaction.
