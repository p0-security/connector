# p0-connector-pg-vaulted

> **Not run against AWS yet.** The connector validates an install, lists a target's grantable
> roles and databases, grants and revokes. All of it is measured against PostgreSQL in Docker
> and a Secrets Manager in memory, and none of it against RDS or AWS. See
> [Not implemented yet](#not-implemented-yet).

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
  database's own, and the manager can grant it and hand a grant login's objects to it. See
  [Grantable roles](#grantable-roles).
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
- **Cleanup**: what follows the database cutoff. It deletes the grant secret, hands what the
  login owns to `objectOwner`, and drops the login. A login that owns nothing needs no owner.

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

The `<target id>` segment must be the request's `targetId`. When `target.managerSecret` is a
secret P0 names, its `<vpc id>` must be `secretName`'s and its `<target id>` must be `targetId`.
A call that breaks either rule, `getUser`, `createUser`, `setPoliciesForUser` and `deleteUser`
alike, is refused with `validation_error` and a payload of `{ host }`, before any call to
Secrets Manager or PostgreSQL. That catches a request that pairs one target with another
target's grant secret or manager secret by mistake. It cannot stop a control plane that sends
them all wrong together: the fields come from the same request, so a request that names another
target in `targetId`, in `secretName` and in the manager secret passes the checks. A secret RDS
manages names no target, so nothing ties it to one. Install validation and `list` take a target
with no `targetId` or `secretName`, so only the manager secret's pattern applies there.

### Lifecycle

`getUser`, `createUser`, and `setPoliciesForUser` with policies are the grant path.
`setPoliciesForUser` with no policies and `deleteUser` are the revoke path. P0 revokes with
`identifyUser`, `setPoliciesForUser` with no policies, `identifyUser`, then `deleteUser`, and
skips the step after an `identifyUser` that finds no login. The resource-root primitives map to
a grant's lifecycle like this:

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

- `setPoliciesForUser` with no policies performs the database cutoff. With no login it does
  nothing. Otherwise, whatever state the login is in:
  1. In a transaction of its own, it revokes every membership the manager granted the login,
     and reads them again to be sure none is left. See
     [The manager's grants](#the-managers-grants). A revoke does not wait for the lock a
     session of the login can hold on the login's own row (see [Sessions](#sessions)), so the
     login cannot stall this step, and from its commit on the login holds none of the approved
     roles. A failure here is kept, and the call goes on to step 2.
  2. In a transaction of its own, it sets the login to
     `NOLOGIN CONNECTION LIMIT 0 PASSWORD NULL`, waiting at most 2 seconds for a lock
     (`lock_timeout`). A session of the login can hold a lock on the login's own row: a login
     may `ALTER ROLE` itself and keep the transaction open, and the manager's `ALTER ROLE` then
     waits for it. When the statement fails for want of the lock, or is cancelled (SQLSTATE
     class `55` or `57`), the connector ends the login's sessions and runs it again, for at
     most 3 attempts in all. Any other failure is thrown at once, and so is a stall of the
     third attempt. Then the login can still sign in, so that P0 tries again. See
     [Sessions](#sessions).
  3. After the commit of step 2, it ends the login's sessions: `pg_terminate_backend` on every
     `pg_stat_activity` row whose `usename` is the login. This runs whether or not step 1 or
     step 2 failed, so that no failure leaves a session open.
  4. It counts the login's sessions. Then it waits 200 ms, ends what it finds and counts
     again, until a count after the first is 0. When sessions remain after 10 counts, it
     throws `upstream_unavailable` with `{ login, sessions }`, so that P0 tries again.

  When more than one step fails, the call throws the failure of step 2, else of step 1, else
  of steps 3 and 4: a login that can still sign in is the worst outcome, so a later failure
  never replaces an earlier one. A failed step 1 leaves the login retired, with no session, and
  the memberships it did not revoke, which the next call revokes. A step 2 that fails on every
  attempt leaves the login active, with no approved role and no session (unless it signed in
  again), which the next call retires.

  Step 2 commits before step 3 because PostgreSQL then refuses every new sign-in. It does not
  come first by much: a sign-in that PostgreSQL let in just before the commit shows in
  `pg_stat_activity` a few milliseconds after it. That is why every count ends what it finds,
  and why the first count alone never confirms the cutoff. See [Sessions](#sessions).

  Each step is safe to repeat, and running the cutoff again changes nothing.

- `deleteUser` performs the cleanup. It refuses a login that has not been cut off, prepared or
  active, with `dependency_violation`, and changes nothing. With no login it deletes the grant
  secret, if there is one, and succeeds. For a retired login, in this order:
  1. It checks `objectOwner` against the [grantable roles](#grantable-roles) at that moment.
     When it is not one, the owner cannot take anything over, so it reads
     [what the login owns](#what-the-login-owns). When the login owns something, in any
     database, it refuses with `validation_error`, and the cleanup never drops an object.
     Nothing is written before this. A login that owns nothing goes on to step 2, which is how
     a grant that failed because its role was not grantable gets cleaned up: the app sends that
     role as `objectOwner`.
  2. It deletes the grant secret, at once and with no recovery window. A secret that is already
     gone is deleted.
  3. It grants the login to the manager. See
     [What the connector grants itself](#what-the-connector-grants-itself).
  4. With an `objectOwner` that is not a grantable role, it ends the login's sessions, the way
     the cutoff does, so that nothing can create an object from here on.
  5. In every database of the target that the manager can connect to, in one transaction each,
     it runs `REASSIGN OWNED BY <grant login> TO <objectOwner>`, then
     `DROP OWNED BY <grant login>`. With an `objectOwner` that is not a grantable role it
     skips the `REASSIGN OWNED`, and reads again what the login owns in that database: when it
     owns something, it refuses as in step 1 and drops nothing, and otherwise `DROP OWNED`
     takes only the privileges the login was granted. It signs in to each with the manager's
     credential, which it reads once. The databases are the ones that are not templates, allow
     connections, and give the manager `CONNECT`. `rdsadmin` is never one.
  6. It ends any session of the login that is still open, the way the cutoff does, and throws
     `upstream_unavailable` when one will not end. See [Sessions](#sessions).
  7. It drops the login, and with it the grant of step 3.

  A step that fails throws, and the next call starts from the state it finds. `getUser` finds a
  retired login without its secret, so a cleanup that stops after step 2 is found and finished.

  PostgreSQL refuses step 7 while anything still depends on the login, and `deleteUser` then
  throws `dependency_violation`. The login stays retired. Two things cause it, as measured:
  - The login owns something in a database the cleanup did not reach, because the manager
    cannot connect to it.
  - Someone other than the manager granted the login a privilege directly, such as
    `GRANT CONNECT ON DATABASE`. `DROP OWNED` run by the manager leaves a privilege whose
    grantor's privileges the manager does not hold. The grantor has to revoke it.

- `list` returns, for a target, its grantable roles (`type: "role"`) or the databases the
  manager can connect to (`type: "database"`), each as `{ key, value }` with the name in both.
  The databases are the ones the cleanup reaches: not templates, allowing connections, giving
  the manager `CONNECT`, and never `rdsadmin`. A database the manager cannot connect to is not
  offered, so that nobody picks one that no grant can work in.

The perimeter's `provisionUser` is `getUser`, then `createUser` when no login is found, and its
`identifyUser` is `getUser`.

The P0 control plane must serialize calls for the same grant login. It may repeat any call:
each primitive reads the state again and ends in the same place.

### Grant login states

A grant login is in exactly one state. The connector reads it from `pg_roles` on each call
(`rolcanlogin` and `rolconnlimit`) and stores it nowhere else.

| State    | In PostgreSQL                                      | `getUser`                                                 | `createUser`                               | `setPoliciesForUser` with policies | `setPoliciesForUser` with no policies  | `deleteUser`                                  |
| -------- | -------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------ | ---------------------------------- | -------------------------------------- | --------------------------------------------- |
| absent   | No role of that name.                              | `null`.                                                   | Creates the login, prepared.               | Refuses: `object_not_found`.       | Does nothing.                          | Deletes the grant secret, if there is one.    |
| prepared | The role exists, `NOLOGIN`, connection limit `-1`. | The login when its grant secret has a value, else `null`. | Sets a new password, deadline and comment. | Grants, then activates.            | Cuts off. The login is retired.        | Refuses: `dependency_violation`.              |
| active   | The role exists, `LOGIN`.                          | The login.                                                | Refuses: `dependency_violation`.           | Grants, and sets the deadline.     | Cuts off. The login is retired.        | Refuses: `dependency_violation`.              |
| retired  | The role exists, `NOLOGIN`, connection limit `0`.  | The login.                                                | Refuses: `dependency_violation`.           | Refuses: `dependency_violation`.   | Cuts off again, which changes nothing. | Cleans up. The login and its secret are gone. |

`CONNECTION LIMIT 0` is the mark of a retired login. Only the database cutoff sets it. Nothing
the connector runs clears it, so a retired login is never activated and never given a password.
A role that cannot log in and has any other connection limit also counts as retired: only a
login as `createUser` leaves it is prepared.

### Statements

The connector puts no value into SQL itself (`src/postgres/statement.ts`):

- A catalog query takes its values as bindings. So do the statements that end and count a
  login's sessions, and the one that sets the cutoff's lock timeout (`set_config`, because `SET`
  takes no binding).
- `CREATE ROLE`, `ALTER ROLE`, `COMMENT`, `GRANT`, `REVOKE`, `REASSIGN OWNED`, `DROP OWNED`
  and `DROP ROLE` take no bindings, so PostgreSQL builds each one. The connector runs
  `SELECT format(<template>, <bindings>)` with a template that is a constant in the code, `%I`
  for a name and `%L` for a literal, then runs the text that comes back. A name must also be
  one a policy can hold. See [Contract](#contract).
- The password never reaches PostgreSQL. The connector computes its SCRAM-SHA-256 verifier
  (`src/postgres/scram.ts`) and sends that as the `PASSWORD`, which PostgreSQL stores as it is.
  So the password is in no server log and no `pg_stat_statements` row. The verifier is in the
  statement's text, so the connector never logs a statement, and no error it throws holds one.

### Failed steps

A failure of `setPoliciesForUser` with no policies or of `deleteUser` is a `ConnectorError`
whose payload names where it came from: the step in `step`, and for a step that works in one
database, the database it was working in, in `database`, which need not be the request's
`target.database`. The error keeps its type, its message and its other payload keys
(`sqlState`, `login`, `sessions`, `rolename`, `state`). Neither value is sensitive, and neither
is an object's name. A failure that is not a `ConnectorError` is thrown as it is. The steps
(`REVOKE_STEPS` in `src/revoke-step.ts`):

| `step`            | Operation | What it was doing                                                                                                                                                                                                                  | `database` |
| ----------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `read_login`      | both      | Reading the manager secret, signing in to the target and looking up the grant login. A `deleteUser` refusal of a login that has not been cut off is also this step.                                                                | no         |
| `revoke_roles`    | cutoff    | Taking back the memberships the manager granted the login (step 1).                                                                                                                                                                | no         |
| `retire_login`    | cutoff    | Setting the login to `NOLOGIN CONNECTION LIMIT 0 PASSWORD NULL`, with its attempts (step 2).                                                                                                                                       | no         |
| `end_sessions`    | both      | Ending and counting the login's sessions: between two attempts of `retire_login` and after it (steps 3 and 4) in the cutoff, and in `deleteUser` before anything is handed over (step 4) and before the login is dropped (step 6). | no         |
| `read_ownership`  | cleanup   | Checking `objectOwner` against the grantable roles and, when it is not one, reading what the login owns (step 1).                                                                                                                  | no         |
| `delete_secret`   | cleanup   | Deleting the grant secret (step 2).                                                                                                                                                                                                | no         |
| `take_privileges` | cleanup   | Granting the login to the manager (step 3).                                                                                                                                                                                        | no         |
| `list_databases`  | cleanup   | Listing the databases the manager can connect to.                                                                                                                                                                                  | no         |
| `release_owned`   | cleanup   | `REASSIGN OWNED` and `DROP OWNED` in one database, with the sign-in to it (step 5).                                                                                                                                                | yes        |
| `drop_login`      | cleanup   | `DROP ROLE` (step 7).                                                                                                                                                                                                              | no         |

When a call fails, the connector has logged an info line for each durable point it passed: the
grant secret deleted, the roles revoked (with the list), the login retired, each database
released (with the database's name in `database`) and the login dropped. None holds a statement.
Each session of the connector's own logs with the database it is signed in to, so a line about
a connection that would not close, or a transaction that would not roll back, names it.

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
   connector creates a probe role named like a grant login, grants it to the manager as under
   [What the connector grants itself](#what-the-connector-grants-itself), reassigns what the
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
- The manager can hand a grant login's objects to it, which is what `REASSIGN OWNED` asks of
  the new owner:
  - From PostgreSQL 16, the manager can `SET ROLE` to the role
    (`pg_has_role(current_user, role, 'SET')`). A role granted to the manager `WITH SET FALSE`
    is not grantable.
  - Before PostgreSQL 16, the manager holds the role's privileges
    (`pg_has_role(current_user, role, 'USAGE')`). A role the manager reaches only through a
    `NOINHERIT` role is not grantable, and no role is for a `NOINHERIT` manager.
  - A superuser manager can hand objects to every role.

The last rule is there so that the connector never has to grant the manager a role. The cleanup
reassigns a grant login's objects to an approved role, and an approved role is a grantable
role, so the manager already holds what the reassign needs.

`setPoliciesForUser` checks each policy's role by the same rule, with the name as a binding
(`IS_GRANTABLE_ROLE_SQL`), so a grant never reaches a role `list` would not offer. `deleteUser`
checks `objectOwner` by it too.

### What the login owns

The cleanup tells whether the grant login owns anything from `pg_shdepend`
(`OWNS_ANYTHING_SQL` and `OWNS_HERE_SQL` in `src/postgres/catalog.ts`): a row with `deptype`
`o`, `refclassid` `pg_authid` and `refobjid` the login's oid is an ownership. As measured on
PostgreSQL 14.25 and 16.16, as a manager that is not superuser and has `CREATEROLE`:

- The manager can read `pg_shdepend`. It is one catalog for the whole server, and the manager
  sees the rows of every database from any connection, whether or not it can connect to that
  database. `dbid` is the database, and `0` marks a shared object such as a database.
- It showed the ownership of a schema, a table, a sequence, a view, a function, an enum type, a
  domain, a default privileges entry, a large object, a table in a second database and an owned
  database. A privilege granted to the login is `deptype` `a`, which `DROP OWNED` takes and is
  not an ownership.
- A login that owns nothing has no row of type `o`.

The cleanup reads it for every database before it writes anything, and again in each database
inside the transaction that runs `DROP OWNED`. Nothing has measured it on RDS, where the
installer is not superuser. If the manager cannot read it, the read fails, and the cleanup
throws `insufficient_privileges` and drops nothing.

### The manager's grants

`setPoliciesForUser` revokes only a membership the manager granted
(`MANAGER_GRANTED_ROLES_SQL`): one whose grantor is the manager, or a role whose privileges the
manager holds. With policies it revokes the ones no policy names, and with no policies it
revokes them all. A membership someone else granted the login stays until the login is dropped.
The query returns one row for each role and grantor.

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

### Sessions

The database cutoff ends a login's sessions with `pg_terminate_backend`, as a manager that is
not superuser and holds `pg_signal_backend`. As measured on PostgreSQL 14.25, 16.16 and 17.12,
on one machine, with the connector's statements run by hand:

- The manager sees every session's `pid` and `usename` in `pg_stat_activity`, and
  `pg_terminate_backend` returned `true` for each session of the login.
- A session that was ended stays in `pg_stat_activity` until its backend has exited. An idle
  session and one idle in a transaction were gone within 5 ms, one in `pg_sleep` within 10 ms,
  and one in a CPU-bound query within 135 ms.
- An idle client sees its connection die with SQLSTATE `57P01`.
- A sign-in with the old password after the cutoff is refused with `28P01`, because the
  password is cleared.
- The commit does not stop every sign-in at once. PostgreSQL lets a sign-in in before its
  session shows in `pg_stat_activity`, so one that got in just before the commit shows after
  it. With 30 sign-ins racing each cutoff on PostgreSQL 14.25 and 16.16, ending the sessions
  once and trusting the first count of 0 left a session of the login alive after 4 of 700
  cutoffs on 14.25 and 8 of 700 on 16.16. Where it was timed, such a session first showed 5 to
  12 ms after the commit returned. Ending the sessions on every count, and never trusting the
  first, left none in 300 cutoffs on each version.
- PostgreSQL drops a role that still has an open session, and the session goes on, with no
  `usename`, where no later call can find it. So the cleanup refuses a login that has not been
  cut off, and ends the login's sessions once more just before it drops the login.

- A session of the login can hold a lock that stalls the retirement. A login may `ALTER ROLE`
  itself, so a session that did that in a transaction it keeps open holds the row, and the
  manager's `ALTER ROLE` waits for it until `statement_timeout`. The statement then fails with
  `57014` and the login can still sign in. Ending the login's sessions first lets the same
  statement succeed at once. So the cutoff waits for the lock 2 seconds, then ends the
  sessions and tries again, for at most 3 attempts. On PostgreSQL 14 and 16, in the integration
  tests, a session that held the row that way made the first attempt fail with `55P03` after 2
  seconds, and the cutoff then completed. A login that signs in again between two attempts and
  takes the lock again can still stall the cutoff. It is bounded at three attempts, each
  waiting 2 seconds, and the call then throws, so that P0's next call tries again. In the
  integration tests, with a login that took the lock again each time its sessions ended, the
  call threw `upstream_unavailable` from a `55P03`, with the roles already taken back.
- A membership `REVOKE` does not wait for that lock. On PostgreSQL 14.25 and 16.16, a
  manager's `REVOKE <role> FROM <login>` completed in under 1 ms while a session of the login
  held a lock on its own row, in an open transaction that ran `ALTER ROLE CURRENT_USER
PASSWORD '...'`, where the manager's `ALTER ROLE` waited until its timeout. That is why the
  cutoff revokes the memberships first: a login that stalls every attempt to retire it still
  loses the approved roles.

Session termination covers the instance the connector is connected to: `pg_stat_activity` and
`pg_terminate_backend` act on that instance's backends and no other. On an Aurora cluster, a
grant login created on the writer can also sign in to the reader instances. The connector does
not see or end sessions there. This is not measured on Aurora. The cutoff's `NOLOGIN` and
cleared password reach a reader by replication, so a new sign-in there is refused once the
reader has applied them (inferred, not measured). An open session on a reader stays. An
operator should give the grant login no network path to the readers, or treat a target as the
writer only.

The wait between two counts is a margin, not a proof. A sign-in that took longer than 200 ms
to show after the commit, and showed only after a count of 0, would outlive the cutoff. The
cleanup is a later call, so by then such a session shows, and the cleanup ends it before the
login is dropped.

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

| The manager needs                     | PostgreSQL 14                                                                                                   | PostgreSQL 16 and 17                                                                                                                        |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `CREATEROLE`                          | Required.                                                                                                       | Required.                                                                                                                                   |
| `pg_signal_backend`                   | Required.                                                                                                       | Required, and not `WITH INHERIT FALSE`: a membership the manager does not inherit cannot signal a backend.                                  |
| The `INHERIT` attribute, the default  | Required. A `NOINHERIT` manager can use neither `pg_signal_backend` nor the privileges `REASSIGN OWNED` needs.  | Not required, but a grant to a `NOINHERIT` manager is `INHERIT FALSE` unless it says `WITH INHERIT TRUE`, and `pg_signal_backend` needs it. |
| `ADMIN OPTION` on each approved role  | Required by the connector, which offers no other role. PostgreSQL itself would let `CREATEROLE` grant the role. | Required.                                                                                                                                   |
| To hand objects to each approved role | The role's privileges, which the grant above gives a manager that has `INHERIT`.                                | `SET ROLE` to the role, which the grant above gives unless it says `SET FALSE`. `WITH ADMIN OPTION, INHERIT FALSE` is enough.               |

A manager that holds an approved role's privileges also cleans up better. `DROP OWNED` run by
the manager takes a privilege from the grant login only when the manager holds the privileges
of the role that granted it. A grant login can give itself a privilege on a table its approved
role owns. On PostgreSQL 16.16 and 17.12, with the approved role granted to the manager
`WITH ADMIN OPTION, INHERIT FALSE`, `DROP OWNED` left that privilege and `DROP ROLE` then
failed. With the grant as written above, it took the privilege and the login was dropped.

#### What the connector grants itself

The connector makes one grant to the manager: the grant login itself. `REASSIGN OWNED` and
`DROP OWNED` need the manager to hold the login's privileges, and creating a role does not give
them from PostgreSQL 16 (`takePrivilegesStatement` in `src/postgres/catalog.ts`). PostgreSQL
puts in the name, quoted where it needs to be. See [Statements](#statements).

| Statement                         | PostgreSQL 14                         | PostgreSQL 16 and 17                                    |
| --------------------------------- | ------------------------------------- | ------------------------------------------------------- |
| Take the grant login's privileges | `GRANT <grant login> TO current_user` | `GRANT <grant login> TO current_user WITH INHERIT TRUE` |

- The cleanup runs it on the retired login and commits it, because every database needs it.
  The grant goes when the login is dropped. A cleanup that stops between the two leaves the
  manager a member of a retired login, which can do nothing, until the next call drops it.
- Install validation runs it on its probe role, in the transaction it rolls back.
- It is not a membership of the grant login, so `setPoliciesForUser` neither sees nor revokes
  it.

The connector grants the manager nothing else. In particular it does not grant the manager an
approved role in order to reassign to it. That grant would stay, and would let the manager act
as the approved role from then on. A role the manager cannot hand objects to is instead not a
[grantable role](#grantable-roles). After a grant and its revoke, the manager's memberships and
every other role's are exactly what they were before, which the integration tests check on
PostgreSQL 14 and 16.

What `REASSIGN OWNED BY <grant login> TO <owner>` needs, as measured. Each setup ran as a
manager that is not superuser, has `CREATEROLE`, and created the login, on the `postgres:14`,
`postgres:16` and `postgres:17` Docker images (14.25, 16.16 and 17.12). The first four rows
ran on install validation's probe role, between `BEGIN` and `ROLLBACK`. The others ran on a
login that owned a table, with the grant of the login to the manager already made. "Grantable"
is what `IS_GRANTABLE_ROLE_SQL` answered for `owner`:

| Setup                                                                             | PostgreSQL 14                                          | PostgreSQL 16 and 17                                                |
| --------------------------------------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------- |
| No grant of the login to the manager                                              | `permission denied to reassign objects`                | `permission denied to reassign objects`                             |
| `GRANT <login> TO current_user`                                                   | Passes.                                                | Passes, but fails as above for a `NOINHERIT` manager.               |
| `GRANT <login> TO current_user WITH INHERIT TRUE`                                 | Syntax error.                                          | Passes, for a `NOINHERIT` manager too. `SET FALSE` does not matter. |
| `GRANT <login> TO current_user WITH INHERIT FALSE, SET TRUE`                      | Syntax error.                                          | `permission denied to reassign objects`                             |
| `owner` was granted to the manager `WITH ADMIN OPTION`                            | Grantable. Passes.                                     | Grantable. Passes, for a `NOINHERIT` manager too.                   |
| The same, and the manager is `NOINHERIT`                                          | Not grantable. `permission denied to reassign objects` | Grantable. Passes.                                                  |
| `owner` was granted `WITH ADMIN OPTION, INHERIT FALSE`                            | Syntax error.                                          | Grantable. Passes, for a `NOINHERIT` manager too.                   |
| `owner` was granted `WITH ADMIN OPTION, SET FALSE`, with or without `INHERIT`     | Syntax error.                                          | Not grantable. `must be able to SET ROLE "<owner>"`                 |
| `ADMIN OPTION` on `owner` only through a `NOINHERIT` role the manager is in       | Not grantable. `permission denied to reassign objects` | Grantable. Passes: inheritance is set on each grant.                |
| `ADMIN OPTION` on `owner` only through a role the manager is in and inherits      | Grantable. Passes.                                     | Grantable. Passes.                                                  |
| `ADMIN OPTION` on `owner` only through a role granted to the manager `SET FALSE`  | Syntax error.                                          | Not grantable. `must be able to SET ROLE "<owner>"`                 |
| `ADMIN OPTION` on `owner` only through a role the manager does not inherit        | Not applicable: no grant sets inheritance.             | Not grantable, because `GRANT` is refused. The reassign passes.     |
| The manager holds no grant of `owner`                                             | Not grantable. `permission denied to reassign objects` | Not grantable. `must be able to SET ROLE "<owner>"`                 |
| The login owns a table. The manager reassigns, then `DROP OWNED` and `DROP ROLE`. | The table's owner is `owner`, and the login is gone.   | The table's owner is `owner`, and the login is gone.                |

In every setup measured, the reassign passed for a grantable `owner`. The `reassign_owned`
check stays because it runs the real statements on the real target, which no catalog query
stands in for.

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
- `secretsmanager:DeleteSecret` on the same secrets. The cleanup deletes a grant secret with
  `ForceDeleteWithoutRecovery`, in the region the request names.

The `*` covers the suffix Secrets Manager adds to each secret's name. The role must not be able to
read a secret under `p0/secrets/postgres/<vpc id>/`. The connector has no code that reads one.

A manager secret must be in the connector's account. A secret in another account is readable only
with a resource policy on the secret that lets the connector's role read it, and only when a
customer-managed KMS key encrypts it, since `aws/secretsmanager` cannot be used from another
account.

## Tests

The unit tests run with the repository's `yarn :test`. They reach Secrets Manager and
PostgreSQL through fakes that the routers take as `dependencies`.

The integration tests (`src/**/*.integration.test.ts`) run install validation, `list`, the
grant path and the revoke path against PostgreSQL 14 and 16 in Docker, as a manager that is
not superuser. They sign in as the grant login with the password the connector stored, which
the images check by SCRAM-SHA-256, and hold sessions open across a cutoff. Secrets Manager is
the fake. They also passed once against the `postgres:17` image (17.12), which
`integration-db.sh` does not start. CI runs them in
`.github/workflows/test-pg-vaulted-integration.yaml`, on a pull request that changes this
service, `connector-core` or `secret-manager-client`. The unit tests' fake answers a catalog
query by the identity of its SQL constant, so only these tests run the SQL. To run them
yourself, from this directory:

```sh
./scripts/integration-db.sh up
yarn test:integration
./scripts/integration-db.sh down
```

`integration-db.sh up` starts one server per version on `127.0.0.1`, at ports 54314 and 54316.
The tests reach them without TLS through `connectWith`, the one way around the shipped
driver's TLS, which no request can take.

## Not implemented yet

Every primitive is implemented. What is not done, or not measured:

- Nothing has run against RDS or Aurora. The measurements here are from the `postgres` Docker
  images, where the manager's setup was done by a real superuser. On RDS the installer is
  `rds_superuser`, which is not superuser, and RDS adds its own roles, sessions and the
  `rdsadmin` database.
- Nothing has run against AWS Secrets Manager. The tests use a fake of the shared client and of
  `DescribeSecret`. The IAM actions above are from the calls the code makes, not from a policy
  that was tried.
- The Lambda container image, its Terraform, and the P0 control plane's side of the contract
  are not in this package.
- The database cutoff has no proof that a sign-in cannot outlive it. See
  [Sessions](#sessions).
- The cutoff ends the sessions of the instance the connector is connected to, and no other. On
  Aurora the grant login can also sign in to the readers, where nothing ends its sessions. See
  [Sessions](#sessions).
- The cleanup cannot take a privilege that a role whose privileges the manager does not hold
  granted the login, and cannot reach a database the manager cannot connect to. In both cases
  `deleteUser` throws `dependency_violation` on every call until someone with the privilege
  steps in. The error names the step (`drop_login`) and the SQLSTATE, and a failure inside a
  database also names the database (see [Failed steps](#failed-steps)). It still does not name
  the object, and a `DROP ROLE` that PostgreSQL refuses does not name a database either.
- A grant login that owns an object while `objectOwner` is not a grantable role is refused, on
  every call, with `validation_error`. The cleanup never drops an object, so the login and its
  secret stay until someone hands the objects to another role, or the owner becomes grantable.
