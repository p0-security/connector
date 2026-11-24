# p0-connector-pg-vaulted

> **Contract only.** This package defines the connector's schemas, router and types. Every
> operation that reaches PostgreSQL or AWS Secrets Manager is a stub that throws. See
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
- **Approved role**: an existing customer-owned database role a grant was approved for. The
  connector grants it, and never creates or alters it.
- **Grantable role**: a role the manager holds `ADMIN OPTION` on, so one a grant can be approved
  for.
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

The `<target id>` segment must be the request's `targetId`. The grant path is to compare the
two, and refuse a request whose grant secret belongs under another target. It is to refuse, the
same way, a manager secret P0 names whose `<vpc id>` is not `secretName`'s, or whose
`<target id>` is not `targetId`. A secret RDS manages names no target, so nothing ties it to
one. Install validation and `list` take a target with no `targetId` or `secretName`, so only the
manager secret's pattern applies there.

### Lifecycle

Only `validation` is implemented. The other resource-root primitives are to map to a grant's
lifecycle like this:

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
- `list` returns, for a target, its grantable roles (`type: "role"`) or its databases
  (`type: "database"`).

The perimeter's `provisionUser` is `getUser`, then `createUser` when no login is found, and its
`identifyUser` is `getUser`.

The P0 control plane must serialize calls for the same grant login.

### Install validation

`pg-vaulted.install.validation.get` takes `{ target }`, the same `target` as the request
context's, and is to write nothing. It is to run these checks in order, and a failure names its
check in `payload.step` (`PG_VAULTED_INSTALL_STEPS`):

1. `manager_secret`: the connector reads the manager secret, and its value parses.
2. `sign_in`: the manager authenticates to the target.
3. `create_role`: the manager can create roles (`CREATEROLE`).
4. `signal_backend`: the manager can end other logins' sessions (`pg_signal_backend`).
5. `reassign_owned`: the manager can hand a grant login's objects to a grantable role.

Once every check has passed it returns `{ grantableRoles }`.

## IAM

The connector's execution role will need:

- `secretsmanager:GetSecretValue` on
  `arn:<partition>:secretsmanager:<region>:<account>:secret:p0/install/postgres/<vpc id>/*`,
  plus the ARN of each RDS-managed manager secret that the VPC's targets use, and on no other
  secret. A manager secret that a customer-managed KMS key encrypts also needs `kms:Decrypt` on
  that key.
- `secretsmanager:CreateSecret`, `secretsmanager:PutSecretValue`,
  `secretsmanager:DescribeSecret` and `secretsmanager:DeleteSecret` only on
  `arn:<partition>:secretsmanager:<region>:<account>:secret:p0/secrets/postgres/<vpc id>/*`.

The `*` covers the suffix Secrets Manager adds to each secret's name. The role must not be able to
read a secret under `p0/secrets/postgres/<vpc id>/`.

A manager secret must be in the connector's account. A secret in another account is readable only
with a resource policy on the secret that lets the connector's role read it, and only when a
customer-managed KMS key encrypts it, since `aws/secretsmanager` cannot be used from another
account.

## Not implemented yet

- `getUser`, `createUser`, `setPoliciesForUser`, `deleteUser` and `list` throw
  `pg-vaulted <operation> is not implemented`. Only the request parsing and the user namespace
  check run before they do.
- `install.validation.get` parses its input and then throws the same error.
- The manager secret's value has no format yet.
- The package depends on no PostgreSQL driver and no Secrets Manager client.
- No image is built: the service is not in `.github/workflows/docker.yaml`.
