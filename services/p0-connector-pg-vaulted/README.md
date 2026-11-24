# p0-connector-pg-vaulted

> **Partly implemented.** The connector signs in as the manager, validates an install, lists a
> target's grantable roles and databases, and grants: it prepares a grant login, stores its
> password and activates it. It cannot revoke yet. The database cutoff and the cleanup are stubs
> that throw. See [Not implemented yet](#not-implemented-yet).

Vaulted PostgreSQL connector, for PostgreSQL on AWS RDS that does not use IAM database
authentication. For each access grant, the connector creates a PostgreSQL login of the grant's
own and stores its password in the customer's AWS Secrets Manager.

It will ship only as an AWS Lambda container image. Each connector belongs to one VPC, whose id
scopes the secrets it can write.

## Terms

- **Target**: one PostgreSQL instance or cluster P0 manages. Its id in P0 is the target id.
- **Manager**: the database login the connector uses for management operations. Its credential
  never reaches P0.
- **Manager secret**: the AWS Secrets Manager secret that holds one target's manager username
  and password. The connector only reads it.
- **Approved role**: an existing customer-owned database role a grant was approved for. The
  connector grants it, and never creates or alters it.
- **Grantable role**: a role a grant can be approved for. It cannot log in, is not the
  database's own, and the manager can grant it. See [Grantable roles](#grantable-roles).
- **Grant key**: 32 lowercase hex digits, random, chosen by P0.
- **Grant login**: a login role the connector creates for exactly one grant, named
  `p0v_<grant key>`.
- **Grant secret**: the Secrets Manager entry that holds one grant login's password and nothing
  else. Only the connector writes it, and the connector cannot read it back. The value is
  binary (`SecretBinary`): the password's ASCII bytes.
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
| `target`      | `{ host, port, database, managerSecret }`: the target, the database the manager connects to, and the target's manager secret.                                                                     |
| `targetId`    | P0's id of the target: `^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`, the pattern of the `<target id>` segment of a grant secret's name. See [Names](#names).                                                 |
| `secrets`     | `{ manager: "aws", region }`: where the grant secret is written. `manager` here is the secret manager, not the manager login.                                                                     |
| `secretName`  | The grant secret's name. See [Names](#names).                                                                                                                                                     |
| `deadline`    | An ISO 8601 date and time with `Z` or an offset. It becomes the grant login's `VALID UNTIL`. A deadline in the past is accepted.                                                                  |
| `comment`     | Who asked and for which request. Written with `COMMENT ON ROLE`, so the customer's own database audit resolves the grant login without P0.                                                        |
| `objectOwner` | The role that takes over what the grant login owns before the login is dropped. P0 sends exactly one policy, and this is its `rolename`, repeated here because `deleteUser` receives no policies. |

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

Revoke parses the same context as grant, so the parser accepts a past `deadline` and truncates
a `comment` over 1000 characters.

### Names

P0 chooses these names. The connector only checks them, and refuses any other.

- Grant login: `^p0v_[0-9a-f]{32}$` (`GRANT_LOGIN_PATTERN`).
- Grant secret: `p0/secrets/postgres/<vpc id>/<target id>/<grant login>`, that is
  `^p0/secrets/postgres/vpc-[0-9a-f]{8,17}/[A-Za-z0-9][A-Za-z0-9-]{0,62}/p0v_[0-9a-f]{32}$`
  (`GRANT_SECRET_NAME_PATTERN`).
- Manager secret, when P0 names it: `p0/install/postgres/<vpc id>/<target id>/p0manager`, that
  is `^p0/install/postgres/vpc-[0-9a-f]{8,17}/[A-Za-z0-9][A-Za-z0-9-]{0,62}/p0manager$`
  (`MANAGER_SECRET_NAME_PATTERN`).

No manager secret is a grant secret. The two names start differently, and a secret RDS manages
is sent as an ARN, never as a name.

The last segment of a grant secret's name is the grant login. The schema cannot compare the two,
because the login arrives as the user, outside the context, so the user namespace check does:
it refuses a login whose grant secret is another login's. With the connector's IAM scoped to
`p0/secrets/postgres/<its vpc>/`, that keeps one grant's secret from being another's.

The `<target id>` segment must be the request's `targetId`. A grant call whose `secretName`
names another target, `getUser`, `createUser` and `setPoliciesForUser` alike, is refused with
`validation_error` and a payload of `{ host }`, before any call to Secrets Manager or
PostgreSQL. That catches a request that pairs one target with another target's grant secret by
mistake. It cannot stop a control plane that sends both wrong together: both fields come from
the same request, so a request that names another target in `targetId` and in `secretName`
passes the check.

The grant path is to refuse, the same way, a manager secret P0 names whose `<vpc id>` is not
`secretName`'s, or whose `<target id>` is not `targetId`. A secret RDS manages names no target,
so nothing ties it to one. Install validation and `list` take a target with no `targetId` or
`secretName`, so only the manager secret's pattern applies there.

### Lifecycle

`validation`, `list` and the grant path are implemented: `getUser`, `createUser`, and
`setPoliciesForUser` with policies. The revoke path is not: `setPoliciesForUser` with no
policies and `deleteUser` throw. The resource-root primitives map to a grant's lifecycle like
this:

- `validation` namespaces the user: the connector acts only on a login that matches
  `GRANT_LOGIN_PATTERN` and whose grant secret is the one in the context, by id and by body.
- `getUser` finds the grant login, by its [state](#grant-login-states):
  - An active or a retired login is found, whatever became of its grant secret. P0's revoke
    skips the database cutoff and the cleanup when it finds no login, so a login that was ever
    activated must always be found.
  - A prepared login is found only when its grant secret has a value. Otherwise `getUser`
    returns `null`, so that `createUser` finishes a grant that stopped half way.
  - With no login it returns `null`.
- `createUser` prepares the grant login, in this order:
  1. It creates the grant secret with no value, or finds it. A refusal by Secrets Manager
     leaves the database untouched.
  2. It makes a password: 32 random bytes as base64url.
  3. In one transaction, it creates the login unable to log in, with the password,
     `VALID UNTIL` the deadline, and the comment. A prepared login gets a new password,
     deadline and comment instead, because nobody can have used the old password. It refuses
     an active or a retired login with `dependency_violation`, and changes neither. `getUser`
     finds those, so `createUser` meets one only when another call got there first.
  4. It writes the password to the grant secret. For a new login it does so before it commits
     the transaction, and for a prepared login after.

  The order of step 4 is what makes a failed call safe to repeat. A new login's grant secret
  may hold a value from an earlier try. If the login were committed first and the write then
  failed, the next `getUser` would take that old value for the login's password. So a new
  login exists only once its password is stored. A prepared login reaches `createUser` only
  when its secret has no value, so a write that fails after the commit leaves the secret
  without one.

  A call that fails part way therefore leaves no login, or a prepared login whose grant secret
  has no value. Either way the next `getUser` finds nothing, and the next `createUser` starts
  again from step 1.

- `setPoliciesForUser` with policies grants the approved roles, then activates the login, in
  one transaction:
  1. It refuses a login that does not exist with `object_not_found`, and a retired login with
     `dependency_violation`.
  2. It refuses, with `validation_error`, a policy whose role is not a
     [grantable role](#grantable-roles) at that moment.
  3. It makes the roles the manager granted the login equal the policies: it grants the ones
     that are missing and revokes the others, then reads the memberships again and throws
     `dependency_violation`, with `{ login }`, when a role it revoked is still held. It leaves
     a membership the manager did not grant. See [The manager's grants](#the-managers-grants).
  4. It sets the login to `LOGIN`, `VALID UNTIL` the deadline.

  It never changes a password, and running it again changes nothing.

- `setPoliciesForUser` with no policies is the revoke path, which is not implemented. It is to
  perform the database cutoff: it disables the login, clears its password, ends its sessions
  and verifies that none remain. It is to throw when the cutoff cannot be confirmed, so that P0
  keeps retrying.
- `deleteUser` is not implemented. It is to clean up after the database cutoff: delete the
  grant secret, hand what the login owns to `objectOwner` in every database of the target, and
  drop the login, in that order. `getUser` finds a retired login without its secret, so a
  cleanup that stops after the secret is deleted is found and finished by the next call. It is to refuse a login that has not been cut off, and a login that is
  already gone is a success.
- `list` returns, for a target, its grantable roles (`type: "role"`) or its databases that are
  not templates (`type: "database"`), each as `{ key, value }` with the name in both.

The perimeter's `provisionUser` is `getUser`, then `createUser` when no login is found, and its
`identifyUser` is `getUser`.

The P0 control plane must serialize calls for the same grant login. It may repeat any call:
each primitive reads the state again and ends in the same place.

### Grant login states

A grant login is in exactly one state. The connector reads it from `pg_roles` on each call
(`rolcanlogin` and `rolconnlimit`) and stores it nowhere else.

| State    | In PostgreSQL                                      | `getUser`                                                 | `createUser`                               | `setPoliciesForUser` with policies |
| -------- | -------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------ | ---------------------------------- |
| absent   | No role of that name.                              | `null`.                                                   | Creates the login, prepared.               | Refuses: `object_not_found`.       |
| prepared | The role exists, `NOLOGIN`, connection limit `-1`. | The login when its grant secret has a value, else `null`. | Sets a new password, deadline and comment. | Grants, then activates.            |
| active   | The role exists, `LOGIN`.                          | The login.                                                | Refuses: `dependency_violation`.           | Grants, and sets the deadline.     |
| retired  | The role exists, `NOLOGIN`, connection limit `0`.  | The login.                                                | Refuses: `dependency_violation`.           | Refuses: `dependency_violation`.   |

`CONNECTION LIMIT 0` is the mark of a retired login. The database cutoff is to set it. Nothing
the connector runs clears it, so a retired login is never activated and never given a password.
A role that cannot log in and has any other connection limit also counts as retired: only a
login as `createUser` leaves it is prepared.

### Statements

The connector puts no value into SQL itself (`src/postgres/statement.ts`):

- A catalog query takes its values as bindings.
- `CREATE ROLE`, `ALTER ROLE`, `COMMENT`, `GRANT`, `REVOKE` and `REASSIGN OWNED` take no
  bindings, so PostgreSQL builds each one. The connector runs
  `SELECT format(<template>, <bindings>)` with a template that is a constant in the code, `%I`
  for a name and `%L` for a literal, then runs the text that comes back. A name must also be
  one a policy can hold. See [Contract](#contract).
- The password never reaches PostgreSQL. The connector computes its SCRAM-SHA-256 verifier
  (`src/postgres/scram.ts`) and sends that as the `PASSWORD`, which PostgreSQL stores as it is.
  So the password is in no server log and no `pg_stat_statements` row. The verifier is in the
  statement's text, so the connector never logs a statement, and no error it throws holds one.

### Install validation

`pg-vaulted.install.validation.get` takes `{ target }`, the same `target` as the request
context's. It runs these checks in order and stops at the first that fails
(`PG_VAULTED_INSTALL_STEPS`):

1. `manager_secret`: the connector reads `target.managerSecret`, in the region that
   [The manager secret in the request](#the-manager-secret-in-the-request) names, and its value
   parses. See [Manager secret](#manager-secret).
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
network or TLS failure has the error's code in `code`. The error's type is one of these:

| Type                      | When                                                                                                                                                            |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `validation_error`        | The manager secret's value does not parse, or the manager secret is one P0 names and the connector's `AWS_REGION` is not set.                                   |
| `object_not_found`        | The manager secret does not exist, or the target's database does not.                                                                                           |
| `insufficient_privileges` | The connector's role may not read the manager secret, PostgreSQL refuses the manager's sign-in, or the manager lacks a privilege.                               |
| `upstream_unavailable`    | The connector cannot reach Secrets Manager or PostgreSQL, the server's certificate is not one AWS signed, or a statement ran longer than the statement timeout. |
| `unknown`                 | PostgreSQL reported a failure the connector does not map.                                                                                                       |

## Manager

### The manager secret in the request

Each request names its target's manager secret in `target.managerSecret`, in one of the two
forms under [Request context](#request-context). The connector reads that secret on each call
that signs in as the manager:

- A secret P0 names, in the connector's own region: the `AWS_REGION` that Lambda sets. When
  `AWS_REGION` is not set, the call fails at `manager_secret` with `validation_error`, and reads
  nothing.
- A secret RDS manages, in the region its ARN names.

More about the secret:

- The P0 control plane chooses the secret. One connector serves every target in its VPC, and
  keeps no list of targets of its own.
- What keeps a request from naming any other secret is the connector's IAM, not the connector:
  its role can read only the manager secrets the install's Terraform gives it. See [IAM](#iam).
  Secrets Manager refuses a request that names another secret.
- Any other ARN or name is refused before the connector calls Secrets Manager.
- The connector runs in the target's region, and so do the grant secrets: it writes them in
  `secrets.region`, for which P0 sends the database's region. A secret P0 names is read in that
  region too. A secret RDS manages is read in the region its ARN names, which must also be
  reachable from the connector's VPC. From a VPC with no NAT, only the region of its Secrets
  Manager interface endpoint is reachable, since an endpoint's private DNS covers only its own
  region.
- Nothing ties the secret to `target.host`. A request that pairs one target's host with another
  target's manager secret signs in to that host with the other target's credential, which the
  host refuses unless both targets share the login.

### Manager secret

The manager secret's value is JSON with `username` and `password`, both non-empty strings. AWS
writes this shape for a secret that RDS manages, and the customer writes it to a secret P0
names.
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
- The driver is `pg`, which sends a statement's text as it is. A statement that PostgreSQL
  built can hold any character in a literal, and a query builder that rewrites `?` would
  change it.

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

`setPoliciesForUser` checks each policy's role by the same rule, with the name as a binding
(`IS_GRANTABLE_ROLE_SQL`), so a grant never reaches a role `list` would not offer.

### The manager's grants

`setPoliciesForUser` revokes only a membership the manager granted
(`MANAGER_GRANTED_ROLES_SQL`): one whose grantor is the manager, or a role whose privileges the
manager holds. The query returns one row for each role and grantor.

- From PostgreSQL 16, a membership's grantor is the role whose `ADMIN OPTION` the `GRANT` used.
  When the manager holds `ADMIN OPTION` on `reporting` only through `it_group`, its grant of
  `reporting` is recorded as granted by `it_group`. A role can be held through several
  grantors at once. PostgreSQL 16.16 refused the manager's `REVOKE` of a membership a superuser
  granted.
- From PostgreSQL 16, a `REVOKE` without `GRANTED BY` removes only the membership whose
  grantor PostgreSQL infers when it runs, and when none matches it prints a `WARNING` and
  removes nothing, with no error. As measured on 16.16, that happens when the manager's path
  to the role changed since the grant: the connector granted `reporting` through `it_group`,
  and the customer later granted `reporting` to the manager `WITH ADMIN OPTION`. The manager's
  `REVOKE reporting FROM <login>` then left the membership recorded as granted by `it_group`.
  So from 16 the connector revokes each membership as its recorded grantor,
  `REVOKE <role> FROM <login> GRANTED BY <grantor>`. As measured on 16.16, a manager that is
  not superuser can do that when the grantor is itself, or a role whose privileges it
  inherits, whether or not it can `SET ROLE` to it. For a grantor whose privileges it does not
  inherit, PostgreSQL refused it, and the query does not return such a membership.
- Before PostgreSQL 16, the grantor is the login that ran the `GRANT`, and a role is held
  once. As measured on 14.25, a plain `REVOKE` by the manager removed the membership whatever
  its grantor, and `GRANTED BY` made no difference. The connector revokes without it.
- Either way, the connector reads the manager-granted memberships again after the revokes. A
  role it revoked and that is still held fails the call with `dependency_violation`, so that
  a revoke that removed nothing is never taken for one that did. A membership whose grantor's
  name is not one a statement can hold is not revoked, and fails the same way.

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
transaction it rolls back. PostgreSQL puts in each name, quoted where it needs to be. See
[Statements](#statements).

| Statement                         | PostgreSQL 14                                | PostgreSQL 16 and 17                                    |
| --------------------------------- | -------------------------------------------- | ------------------------------------------------------- |
| Take the grant login's privileges | `GRANT <grant login> TO current_user`        | `GRANT <grant login> TO current_user WITH INHERIT TRUE` |
| Take the right to hand to `owner` | `GRANT <owner> TO current_user`              | `GRANT <owner> TO current_user WITH SET TRUE`           |
| Reassign                          | `REASSIGN OWNED BY <grant login> TO <owner>` | `REASSIGN OWNED BY <grant login> TO <owner>`            |

Both grants make the manager a member of another role. Neither is a membership of the grant
login, so `setPoliciesForUser` neither sees nor revokes them.

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

The connector's execution role needs:

- `secretsmanager:GetSecretValue` on
  `arn:<partition>:secretsmanager:<region>:<account>:secret:p0/install/postgres/<vpc id>/*`,
  plus the ARN of each RDS-managed manager secret that the VPC's targets use, and on no other
  secret. A manager secret that a customer-managed KMS key encrypts also needs `kms:Decrypt` on
  that key.
- `secretsmanager:CreateSecret`, `secretsmanager:PutSecretValue` and
  `secretsmanager:DescribeSecret` only on
  `arn:<partition>:secretsmanager:<region>:<account>:secret:p0/secrets/postgres/<vpc id>/*`. A
  grant makes all three calls, in the region the request names.
- `secretsmanager:DeleteSecret` on the same secrets, for the cleanup, which is not implemented
  yet.

The `*` covers the suffix Secrets Manager adds to each secret's name. The role must not be able to
read a secret under `p0/secrets/postgres/<vpc id>/`. The connector has no code that reads one.

A manager secret must be in the connector's account. A secret in another account is readable only
with a resource policy on the secret that lets the connector's role read it, and only when a
customer-managed KMS key encrypts it, since `aws/secretsmanager` cannot be used from another
account.

## Tests

The unit tests run with the repository's `yarn :test`. They reach Secrets Manager and
PostgreSQL through fakes that the routers take as `dependencies`.

The integration tests (`src/**/*.integration.test.ts`) run install validation, `list` and the
grant path against PostgreSQL 14 and 16 in Docker, as a manager that is not superuser. They
sign in as the grant login with the password the connector stored, which the images check by
SCRAM-SHA-256. CI runs them in `.github/workflows/test-pg-vaulted-integration.yaml`, on a pull
request that changes this service, `connector-core` or `secret-manager-client`. The unit tests'
fake answers a catalog query by the identity of its SQL constant, so only these tests run the
SQL. To run them yourself, from this directory:

```sh
./scripts/integration-db.sh up
yarn test:integration
./scripts/integration-db.sh down
```

`integration-db.sh up` starts one server per version on `127.0.0.1`, at ports 54314 and 54316.
The tests reach them without TLS through `connectWith`, the one way around the shipped
driver's TLS, which no request can take.

## Not implemented yet

- `setPoliciesForUser` with no policies and `deleteUser` throw
  `pg-vaulted <operation> is not implemented`. Only the request parsing and the user namespace
  check run before they do. So the connector cannot revoke: it performs no database cutoff,
  deletes no grant secret and drops no grant login.
- Until the cutoff exists, a grant ends only when its deadline passes. `VALID UNTIL` then
  refuses a new sign-in with the password. It does not end a session that is already open.
- `deleteUser` is to run the statements under
  [What the connector grants itself](#what-the-connector-grants-itself) outside a transaction
  that is rolled back. Whether it takes the two grants back afterwards is not decided.
