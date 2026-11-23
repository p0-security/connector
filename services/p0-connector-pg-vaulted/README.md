# p0-connector-pg-vaulted

> **Partly implemented.** The connector signs in as the manager, validates an install and lists
> a target's grantable roles and databases. Every operation that creates, changes or removes a
> grant login is a stub that throws. See [Not implemented yet](#not-implemented-yet).

Vaulted PostgreSQL connector, for PostgreSQL on AWS RDS that does not use IAM database
authentication. For each access grant, the connector is to create a PostgreSQL login of the
grant's own and store its password in the customer's AWS Secrets Manager.

It will ship only as an AWS Lambda container image. Each connector belongs to one VPC, whose id
scopes the secrets it can write.

## Terms

- **Target**: one PostgreSQL instance or cluster P0 manages. Its id in P0 is the target id.
- **Manager**: the database login the connector uses for management operations. Its credential
  never reaches P0.
- **Manager secret**: the Secrets Manager entry that holds one target's manager username and
  password. The connector only reads it.
- **Manager mapping**: the connector's own list of each target's manager secret and target id,
  by the target's host.
- **Approved role**: an existing customer-owned database role a grant was approved for. The
  connector grants it, and never creates or alters it.
- **Grantable role**: a role a grant can be approved for. It cannot log in, is not the
  database's own, and the manager can grant it. See [Grantable roles](#grantable-roles).
- **Grant key**: 32 lowercase hex digits, random, chosen by P0.
- **Grant login**: a login role the connector creates for exactly one grant, named
  `p0v_<grant key>`.
- **Grant secret**: the Secrets Manager entry that holds one grant login's password and nothing
  else. Only the connector writes it, and the connector cannot read it back.
- **Deadline**: the moment a grant's access ends.
- **Prepared login**: a grant login that exists and cannot log in yet.
- **Activation**: turning a prepared login into one that can log in.
- **Database cutoff**: the confirmed state in which a grant login is disabled, its password is
  cleared, and every session it opened is verified gone.
- **Retired login**: a grant login after database cutoff and before cleanup drops it. It is not
  reactivated.

## Contract

The router namespace is `pg-vaulted`. The P0 control plane imports the contract from
`@p0security/p0-connector-pg-vaulted/connector`, which loads no handler.

There is one access type, `role`, on the resource-root perimeter. Its user is the grant login,
and each of its policies is one approved role:

```json
{ "type": "role", "rolename": "analyst" }
```

A role name is 1 to 63 bytes of ASCII letters, digits and `. _ @ + -`, the same rule as
`p0-connector-pg`.

### Request context

Every access call carries this context (`src/context.ts`):

| Field         | Value                                                                                                                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `requestId`   | The P0 request, a non-empty string.                                                                                                                                                               |
| `target`      | `{ host, port, database }`: the target, and the database the manager connects to.                                                                                                                 |
| `secrets`     | `{ manager: "aws", region }`: where the grant secret is written. `manager` here is the secret manager, not the manager login.                                                                     |
| `secretName`  | The grant secret's name. See [Names](#names).                                                                                                                                                     |
| `deadline`    | An ISO 8601 date and time with `Z` or an offset. It becomes the grant login's `VALID UNTIL`. A deadline in the past is accepted.                                                                  |
| `comment`     | Who asked and for which request. Written with `COMMENT ON ROLE`, so the customer's own database audit resolves the grant login without P0.                                                        |
| `objectOwner` | The role that takes over what the grant login owns before the login is dropped. P0 sends exactly one policy, and this is its `rolename`, repeated here because `deleteUser` receives no policies. |

The context does not name the manager secret. The connector looks it up by `target.host` in
the [manager mapping](#manager-mapping), which Terraform sets in the connector's own
environment, so the P0 control plane cannot point the connector at another secret or host. The
mapping also holds the target's id. A grant call is to be refused unless the `<target id>`
segment of `secretName` is that id (see [Names](#names)).

Revoke parses the same context as grant, so the parser accepts a past `deadline` and truncates
a `comment` over 1000 characters.

### Names

P0 chooses both names. The connector only checks them, and refuses any other.

- Grant login: `^p0v_[0-9a-f]{32}$` (`GRANT_LOGIN_PATTERN`).
- Grant secret: `p0/postgres-ai/<vpc id>/<target id>/<grant login>`, that is
  `^p0/postgres-ai/vpc-[0-9a-f]{8,17}/[A-Za-z0-9][A-Za-z0-9-]{0,62}/p0v_[0-9a-f]{32}$`
  (`GRANT_SECRET_NAME_PATTERN`).

The last segment of a grant secret's name is the grant login. The schema cannot compare the two,
because the login arrives as the user, outside the context, so the user namespace check does:
it refuses a login whose grant secret is another login's. With the connector's IAM scoped to
`p0/postgres-ai/<its vpc>/`, that keeps one grant's secret from being another's.

The `<target id>` segment is the same kind of claim: the schema cannot tie it to the target in
`target.host`. The [manager mapping](#manager-mapping) does. It holds each host's target id,
and a grant call whose `secretName` names another target is to be refused with
`validation_error`, before any call to Secrets Manager or PostgreSQL. That keeps a request for
one target from writing a grant secret that belongs under another.

### Lifecycle

Only `validation` and `list` are implemented. The other resource-root primitives are to map to
a grant's lifecycle like this:

- `validation` namespaces the user: the connector acts only on a login that matches
  `GRANT_LOGIN_PATTERN` and whose grant secret is the one in the context, by id and by body.
- `getUser` finds the grant login. It returns the login only when both the login and its grant
  secret exist, so that `createUser` finishes a half-prepared login.
- `createUser` prepares the grant login. It creates the login unable to log in, with a random
  password, `VALID UNTIL` the deadline, and the comment. Then it creates the grant secret and
  writes the password to it. It may reset the password of a prepared login, because nobody can
  have used it.
- `setPoliciesForUser` with policies grants each approved role, then activates the login. It
  is idempotent, and does not change the password of an activated login.
- `setPoliciesForUser` with no policies is the revoke path. It performs the database cutoff: it
  disables the login, clears its password, ends its sessions and verifies that none remain. It
  throws when the cutoff cannot be confirmed, so that P0 keeps retrying.
- `deleteUser` cleans up after the database cutoff. It deletes the grant secret, hands what the
  login owns to `objectOwner` in every database of the target, and drops the login. It refuses a
  login that has not been cut off, and a login that is already gone is a success.
- `list` returns, for a target, its grantable roles (`type: "role"`) or its databases that are
  not templates (`type: "database"`), each as `{ key, value }` with the name in both.

The perimeter's `provisionUser` is `getUser`, then `createUser` when no login is found, and its
`identifyUser` is `getUser`.

The P0 control plane must serialize calls for the same grant login.

### Install validation

`pg-vaulted.install.validation.get` takes `{ target }`. It runs these checks in order and stops
at the first that fails (`PG_VAULTED_INSTALL_STEPS`):

1. `manager_mapping`: the manager mapping parses, and has the target's host.
2. `sign_in`: the connector reads the manager secret, and the manager authenticates to the
   target and runs `SELECT 1`.
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
network or TLS failure has the error's code in `code`. The error's type is one of these:

| Type                      | When                                                                                                                                                            |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `validation_error`        | The manager mapping is not set or does not parse, or the manager secret's value does not.                                                                       |
| `object_not_found`        | The manager mapping has no entry for the host, the manager secret does not exist, or the target's database does not.                                            |
| `insufficient_privileges` | The connector's role may not read the manager secret, PostgreSQL refuses the manager's sign-in, or the manager lacks a privilege.                               |
| `upstream_unavailable`    | The connector cannot reach Secrets Manager or PostgreSQL, the server's certificate is not one AWS signed, or a statement ran longer than the statement timeout. |
| `unknown`                 | PostgreSQL reported a failure the connector does not map.                                                                                                       |

## Manager

### Manager mapping

The connector reads the manager mapping from the environment variable `MANAGER_SECRET_ARNS`: a
JSON object from each target's host to an object with the ARN of that target's manager secret
(`arn`) and the target's id (`targetId`).

```json
{
  "orders.cluster-abc.us-east-1.rds.amazonaws.com": {
    "arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:orders-manager-AbCdEf",
    "targetId": "orders-prod"
  }
}
```

- The connector reads the variable on each call, so a mapping that is not set or does not parse
  fails the call at `manager_mapping`, not the Lambda's start.
- The host lookup ignores case.
- Each `arn` must be a full Secrets Manager ARN in the `aws`, `aws-cn` or `aws-us-gov`
  partition. A secret's name alone is refused.
- Each `targetId` is a target id as a grant secret's name holds it:
  `^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`. It is the `<target id>` segment that this target's grant
  secrets must have. See [Names](#names).
- A value that is a string, such as an ARN alone, is refused.
- The connector reads the secret in the region its ARN names.

### Manager secret

The manager secret's value is JSON with `username` and `password`, both non-empty strings. AWS
writes this shape for a secret that RDS manages and for an "RDS database credentials" secret.
The connector ignores every other key, `host` and `port` included: the target comes from the
request.

```json
{ "username": "p0_manager", "password": "..." }
```

The connector never logs the value, and no error it throws holds the value or the Secrets
Manager error it came with.

### Connection

The connector opens one connection per call, as the manager, to the request's
`target.database`, and closes it when the call ends.

- TLS is always on. The connector verifies the server's certificate against the AWS RDS
  certificate authorities (`aws-ssl-profiles`). No request field and no environment variable
  turns TLS off.
- The connection timeout is 10 seconds and the statement timeout is 15 seconds.

### Grantable roles

`list` with `type: "role"` and install validation's `grantableRoles` come from one query
(`GRANTABLE_ROLES_SQL` in `src/postgres/catalog.ts`). A role is grantable when all of these
hold:

- It cannot log in.
- It is not superuser.
- Its name does not start with `pg_`, `rds` or `p0v_`.
- Its name is one a policy can hold. See [Contract](#contract).
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

The connector's execution role will need:

- `secretsmanager:GetSecretValue` on the manager's secrets, and on no other secret.
- `secretsmanager:CreateSecret`, `secretsmanager:PutSecretValue`,
  `secretsmanager:DescribeSecret` and `secretsmanager:DeleteSecret` on secrets under
  `p0/postgres-ai/<vpc id>/`.

It must not be able to read a secret under `p0/postgres-ai/<vpc id>/`.

## Tests

The unit tests run with the repository's `yarn :test`. They reach Secrets Manager and
PostgreSQL through fakes that the routers take as `dependencies`.

The integration tests (`src/**/*.integration.test.ts`) run install validation and `list`
against PostgreSQL 14 and 16 in Docker, as a manager that is not superuser. CI does not run
them. To run them, from this directory:

```sh
./scripts/integration-db.sh up
yarn test:integration
./scripts/integration-db.sh down
```

`integration-db.sh up` starts one server per version on `127.0.0.1`, at ports 54314 and 54316.
The tests reach them without TLS through `connectWith`, the one way around the shipped
driver's TLS, which no request can take.

## Not implemented yet

- `getUser`, `createUser`, `setPoliciesForUser` and `deleteUser` throw
  `pg-vaulted <operation> is not implemented`. Only the request parsing and the user namespace
  check run before they do.
- The connector writes no grant secret, and creates, changes and drops no grant login.
- `deleteUser` is to run the statements under
  [What the connector grants itself](#what-the-connector-grants-itself) outside a transaction
  that is rolled back. Whether it takes the two grants back afterwards is not decided.
