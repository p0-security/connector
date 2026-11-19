# p0-connector-pg-vaulted

> **Contract only.** This package defines the connector's schemas, router and types. Every
> operation that reaches PostgreSQL or AWS Secrets Manager is a stub that throws. See
> [Not implemented yet](#not-implemented-yet).

Vaulted PostgreSQL connector, for PostgreSQL on AWS RDS that does not use IAM database
authentication. For each access grant, the connector creates a PostgreSQL login of the grant's
own and stores its password in the customer's AWS Secrets Manager.

Ships only as an AWS Lambda container image; no image is published yet. Each connector belongs
to one VPC, whose id scopes the secrets it can write.

## Terms

- **Target**: one PostgreSQL instance or cluster P0 manages.
- **Manager**: the database login the connector uses for management operations. Its credential
  never reaches P0.
- **Approved role**: an existing customer-owned database role a grant was approved for. The
  connector grants it, and never creates or alters it.
- **Grant key**: 32 lowercase hex digits, random, chosen by P0.
- **Grant login**: a login role the connector creates for exactly one grant, named
  `p0v_<grant key>`.
- **Grant secret**: the Secrets Manager entry that holds one grant login's password and nothing
  else. Only the connector writes it, and the connector cannot read it back.
- **Deadline**: the moment a grant's access ends.
- **Activation**: turning a prepared grant login from unable to log in to able to log in.
- **Database cutoff**: the confirmed state in which a grant login is disabled, its password is
  cleared, and every session it opened is verified gone.
- **Retired login**: a grant login after database cutoff and before cleanup drops it. It is
  never reactivated.

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

| Field         | Value                                                                                                                                      |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `requestId`   | The P0 request, a non-empty string.                                                                                                        |
| `target`      | `{ host, port, database }`: the target, and the database the manager connects to.                                                          |
| `secrets`     | `{ manager: "aws", region }`: where the grant secret is written.                                                                           |
| `secretName`  | The grant secret's name. See [Names](#names).                                                                                              |
| `deadline`    | An ISO 8601 date and time with `Z` or an offset. It becomes the grant login's `VALID UNTIL`. A deadline in the past is accepted.           |
| `comment`     | Who asked and for which request. Written with `COMMENT ON ROLE`, so the customer's own database audit resolves the grant login without P0. |
| `objectOwner` | The role that takes over what the grant login owns before the login is dropped: the approved role.                                         |

The context does not name the manager's secret. The connector looks it up by `target.host` in
its own environment, in a mapping that Terraform sets, so the P0 control plane cannot point the
connector at another secret or host.

Revoke parses the same context as grant, so a field that can go stale is never a reason to
refuse: a past `deadline` is accepted, and a `comment` over 1000 characters is truncated.

### Names

P0 chooses both names. The connector only checks them, and refuses any other.

- Grant login: `^p0v_[0-9a-f]{32}$` (`GRANT_LOGIN_PATTERN`).
- Grant secret: `p0/postgres-ai/<vpc id>/<target id>/<grant login>`, that is
  `^p0/postgres-ai/vpc-[0-9a-f]{8,17}/[A-Za-z0-9][A-Za-z0-9-]{0,62}/p0v_[0-9a-f]{32}$`
  (`GRANT_SECRET_NAME_PATTERN`).

The connector's IAM is scoped to `p0/postgres-ai/<its vpc>/`, and the last segment of a grant
secret's name is the grant login, so one grant's secret can never be another's. The schema
cannot compare the secret name with the grant login, because the login arrives as the user,
outside the context. `isGrantSecretOfLogin` makes that comparison, and each handler must call it
before it touches the secret.

### Lifecycle

The resource-root primitives map to a grant's lifecycle like this:

- `validation` namespaces the user: the connector acts only on a login that matches
  `GRANT_LOGIN_PATTERN`, by id and by body.
- `getUser` finds the grant login. It returns the login only when both the role and its grant
  secret exist, so that `createUser` finishes a half-prepared login.
- `createUser` prepares the grant login. It creates the role unable to log in, with a random
  password, `VALID UNTIL` the deadline, and the comment. Then it creates the grant secret and
  writes the password to it. It may reset the password of a prepared login that was never
  activated, because nobody can have used it.
- `setPoliciesForUser` with policies grants each approved role, then activates the login. It
  is idempotent, and never changes the password of an activated login.
- `setPoliciesForUser` with no policies is the revoke path. It performs the database cutoff: it
  disables the login, clears its password, ends its sessions and verifies that none remain. It
  throws when the cutoff cannot be confirmed, so that P0 keeps retrying.
- `deleteUser` cleans up after the database cutoff. It deletes the grant secret, hands what the
  login owns to `objectOwner` in every database of the target, and drops the login. It refuses a
  login that has not been cut off, and a login that is already gone is a success.
- `list` returns, for a target, the roles a grant can be approved for (`type: "role"`) or its
  databases (`type: "database"`).

The perimeter's `provisionUser` is `getUser`, then `createUser` when no login is found, and its
`identifyUser` is `getUser`.

The P0 control plane must serialize calls for the same grant login.

### Install validation

`pg-vaulted.install.validation.get` takes `{ target }` and never writes. It runs these checks
in order, and a failure names its check in `payload.step` (`PG_VAULTED_INSTALL_STEPS`):

1. `manager_mapping`: the target's host is in the connector's manager mapping.
2. `sign_in`: the manager authenticates to the target.
3. `create_role`: the manager can create roles (`CREATEROLE`).
4. `signal_backend`: the manager can end other logins' sessions (`pg_signal_backend`).

Once every check has passed it returns `{ grantableRoles }`: the roles the manager holds
`ADMIN OPTION` on, which are the roles it can hand out.

## IAM

The connector's execution role will need:

- `secretsmanager:GetSecretValue` on the manager's secrets, and on no other secret.
- `secretsmanager:CreateSecret`, `secretsmanager:PutSecretValue`,
  `secretsmanager:DescribeSecret` and `secretsmanager:DeleteSecret` on secrets under
  `p0/postgres-ai/<vpc id>/`.

It must not be able to read a secret under `p0/postgres-ai/<vpc id>/`: the connector writes a
grant login's password and cannot read it back.

## Not implemented yet

- `getUser`, `createUser`, `setPoliciesForUser`, `deleteUser` and `list` throw
  `pg-vaulted <operation> is not implemented`. Only the request parsing and the user namespace
  check run before they do.
- `install.validation.get` parses its input and then throws the same error.
- The manager mapping has no format yet: neither the environment variable that holds it nor the
  shape of its value is defined.
- Nothing calls `isGrantSecretOfLogin` yet.
- The package depends on no PostgreSQL driver and no Secrets Manager client.
- No image is built: the service is not in `.github/workflows/docker.yaml`.
- Install validation does not yet check that the manager can reassign a grant login's objects
  to an approved role.
