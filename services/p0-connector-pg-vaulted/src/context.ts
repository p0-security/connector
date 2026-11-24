import { z } from "zod";

import { isIdentifier } from "./identifier.ts";

/**
 * A grant login's name: `p0v_<grant key>`, where the grant key is 32
 * lowercase hex digits that P0 picks at random. P0 chooses the name; the
 * connector only checks it, and acts on no login outside this namespace.
 */
export const GRANT_LOGIN_PATTERN = /^p0v_[0-9a-f]{32}$/;

export const grantLogin = z.string().regex(GRANT_LOGIN_PATTERN);

// copy of `region` in services/p0-connector-redshift-ai/src/context.ts
// Closed, so that a request can't send the connector's calls to an endpoint
// outside AWS's regional ones.
const REGION = "[a-z]{2}(-[a-z]+)+-\\d{1,2}";

/** A VPC's id, as the `<vpc id>` segment of a secret's name holds it. */
const VPC_ID = "vpc-[0-9a-f]{8,17}";

/** P0's id of a target, as the `<target id>` segment of a secret's name
 * holds it. */
const TARGET_ID = "[A-Za-z0-9][A-Za-z0-9-]{0,62}";

/** A lowercase UUID, as RDS writes one in the name of a secret it manages. */
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

/**
 * The name of a manager secret P0 names:
 * `p0/install/postgres/<vpc id>/<target id>/p0manager`. The customer creates
 * it, in the connector's own account and region.
 */
export const MANAGER_SECRET_NAME_PATTERN = new RegExp(
  `^p0/install/postgres/${VPC_ID}/${TARGET_ID}/p0manager$`
);

/**
 * The full ARN of a manager secret RDS manages, in the `aws`, `aws-cn` or
 * `aws-us-gov` partition. RDS names the secret `rds!db-<uuid>` or
 * `rds!cluster-<uuid>`, and Secrets Manager adds a suffix of six characters.
 */
export const RDS_MANAGER_SECRET_ARN_PATTERN = new RegExp(
  `^arn:aws(-cn|-us-gov)?:secretsmanager:${REGION}:\\d{12}:secret:rds!(db|cluster)-${UUID}-[A-Za-z0-9]{6}$`
);

/**
 * The secret that holds the target's manager login: the name of a secret P0
 * names, or the ARN of a secret RDS manages. Anything else is refused. The
 * connector's IAM limits which secrets it can read.
 */
const managerSecret = z
  .string()
  .refine(
    (secret) =>
      MANAGER_SECRET_NAME_PATTERN.test(secret) ||
      RDS_MANAGER_SECRET_ARN_PATTERN.test(secret),
    "managerSecret must be a name p0/install/postgres/<vpc id>/<target id>/p0manager, or the ARN of a secret RDS manages"
  );

/**
 * One target: a PostgreSQL instance or cluster P0 manages, the database the
 * manager connects to, and the secret that holds the manager's login.
 */
export const target = z.object({
  host: z.string().min(1),
  // copy of `port` in services/p0-connector-pg/src/accesses/common/definition.ts
  // 65535 is the highest TCP port (input validation only)
  port: z.coerce.number().int().min(1).max(65535),
  database: z.string().min(1),
  managerSecret,
});

export type Target = z.infer<typeof target>;

export const installContext = z.object({ target });

export type InstallContext = z.infer<typeof installContext>;

const region = z.string().regex(new RegExp(`^${REGION}$`));

/** Where grant secrets are written: AWS Secrets Manager, in `region`.
 * `manager` is the secret manager, not the manager login. */
const secrets = z.object({ manager: z.literal("aws"), region });

/**
 * A grant secret's name:
 * `p0/secrets/postgres/<vpc id>/<target id>/<grant login>`. No manager secret
 * has a name under `p0/secrets/`, so a grant never writes over the manager's
 * login.
 */
export const GRANT_SECRET_NAME_PATTERN = new RegExp(
  `^p0/secrets/postgres/${VPC_ID}/${TARGET_ID}/p0v_[0-9a-f]{32}$`
);

/**
 * Whether `secretName` is the grant secret of `login`: its last segment is
 * the login. The request-context schema cannot check this, because the grant
 * login arrives as the user, outside the context, so the user namespace check
 * does. It is what keeps one grant's secret from being another's.
 */
export const isGrantSecretOfLogin = (secretName: string, login: string) =>
  secretName.endsWith(`/${login}`);

export const rolename = z
  .string()
  .min(1)
  .refine(isIdentifier, "Invalid role name");

/** The longest comment the connector writes with `COMMENT ON ROLE`. */
const MAX_COMMENT_LENGTH = 1000;

export const requestContext = z.object({
  requestId: z.string().min(1),
  target,
  /** P0's id of `target`. The `<target id>` segment of `secretName`, and of
   * a manager secret P0 names, must be this id. */
  targetId: z.string().regex(new RegExp(`^${TARGET_ID}$`)),
  secrets,
  /** The grant secret P0 names for the grant login. The connector writes the
   * login's password to it and can't read it back. */
  secretName: z.string().regex(GRANT_SECRET_NAME_PATTERN),
  /** The deadline, which becomes the grant login's `VALID UNTIL`. A deadline
   * in the past is never refused: revoke parses this context too, and must
   * not fail on a grant whose deadline has passed. */
  deadline: z.iso.datetime({ offset: true }),
  /** Who asked and for which request, written with `COMMENT ON ROLE` so the
   * customer's own database audit resolves the grant login without P0.
   * Truncated, never refused, for the same reason as the deadline. */
  comment: z.string().transform((text) => text.slice(0, MAX_COMMENT_LENGTH)),
  /** The role that takes over what the grant login owns before the login is
   * dropped. P0 sends exactly one policy, and this is its `rolename`,
   * repeated here because `deleteUser` receives no policies. A login that
   * still owns a table can't be dropped. */
  objectOwner: rolename,
});

export type RequestContext = z.infer<typeof requestContext>;

export const listerQuery = z.object({
  type: z.enum(["role", "database"]),
  context: target,
});

// copy of `listerResponse` in services/p0-connector-pg/src/accesses/common/definition.ts
export const listerResponse = z
  .object({
    key: z.string().min(1),
    value: z.string().min(1),
    group: z.string().min(1).optional(),
  })
  .array();
