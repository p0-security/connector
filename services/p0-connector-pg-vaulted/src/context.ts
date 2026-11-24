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
