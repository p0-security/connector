import { newZodResourceHierarchyParsers } from "@p0security/connector-core";
import type { JsonValue } from "type-fest";
import { z } from "zod";

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
 * The `region` group is the secret's region.
 */
export const RDS_MANAGER_SECRET_ARN_PATTERN = new RegExp(
  `^arn:aws(-cn|-us-gov)?:secretsmanager:(?<region>${REGION}):\\d{12}:secret:rds!(db|cluster)-${UUID}-[A-Za-z0-9]{6}$`
);

/**
 * The secret that holds the target's manager login: the name of a secret P0
 * names, or the ARN of a secret RDS manages. Anything else is refused. The
 * connector's IAM limits which secrets it can read.
 */
export const managerSecret = z
  .string()
  .refine(
    (secret) =>
      MANAGER_SECRET_NAME_PATTERN.test(secret) ||
      RDS_MANAGER_SECRET_ARN_PATTERN.test(secret),
    "managerSecret must be a name p0/install/postgres/<vpc id>/<target id>/p0manager, or the ARN of a secret RDS manages"
  );

/** The connector's IAM allows secret writes only under this prefix. */
export const GRANT_SECRET_PREFIX_PATTERN = new RegExp(
  `^p0/secrets/postgres/${VPC_ID}/${TARGET_ID}$`
);

const grantSecretPrefix = z
  .string()
  .regex(
    GRANT_SECRET_PREFIX_PATTERN,
    "grantSecretPrefix must be p0/secrets/postgres/<vpc id>/<target id>"
  );

export const pgClientParams = z.object({
  p0User: z.string(),
  host: z.string(),
  // 65535 is the highest TCP port (input validation only)
  port: z.coerce.number().int().min(1).max(65535),
  database: z.string(),
  managerSecret,
  cloud: z.enum(["rds", "localhost"]).optional().default("rds"),
});

export const requestContext = z.object({
  requestId: z.string(),
  db: pgClientParams,
  /** The latest end among all active grants that share the login, not only this request's. */
  grantEndsAt: z.iso.datetime({ offset: true }),
  grantSecretPrefix,
});

export type PgRequestContext = z.infer<typeof requestContext>;
export type PgClientParams = z.infer<typeof pgClientParams>;

const username = z.string().min(1);
export const rolename = z.string().min(1);
export const userBody = username;
export const userId = username;
export const resourceId = rolename;
export const resourceBody = rolename;

export const listerResponse = z
  .object({
    key: z.string().min(1),
    value: z.string().min(1),
    group: z.string().min(1).optional(),
  })
  .array();

/**
 * Builds the parsers for a Postgres access type. Every access type shares the
 * same users, resources and request context — a Postgres role — so an access
 * type only supplies its own policy shape and the entities its lister serves.
 */
export const newPgAccessSpec = <
  PolicySchema extends z.ZodType<JsonValue>,
  ListerQuerySchema extends z.ZodType<JsonValue & { type: string }>,
>(
  policy: PolicySchema,
  query: ListerQuerySchema
) => {
  const schema = {
    userBody,
    userId,
    resourceBody,
    policy,
    resourceId,
    listerQuery: query,
    listerResponse,
    requestContext,
  };

  return newZodResourceHierarchyParsers(schema);
};
