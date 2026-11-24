import { z } from "zod";

// copy of `region` in services/p0-connector-redshift-ai/src/context.ts
// Closed, so that a request can't send the connector's calls to an endpoint
// outside AWS's regional ones.
const REGION = "[a-z]{2}(-[a-z]+)+-\\d{1,2}";

/** Where every grant secret's name starts. */
const GRANT_SECRET_PREFIX = "p0/postgres-ai/";

/** A Secrets Manager secret's full ARN, in the `aws`, `aws-cn` or
 * `aws-us-gov` partition. A secret's name alone is refused. */
const MANAGER_SECRET_ARN_PATTERN = new RegExp(
  `^arn:aws(-cn|-us-gov)?:secretsmanager:${REGION}:\\d{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$`
);

/** The secret's name, with the suffix Secrets Manager adds, from an ARN that
 * matches {@link MANAGER_SECRET_ARN_PATTERN}. */
const secretNameOfArn = (arn: string) => arn.split(":")[6] ?? "";

/**
 * The ARN of the secret that holds the target's manager login. The P0
 * control plane names it, as it names the private key secret of the
 * Snowflake and GitHub (AI) connectors, and the connector's IAM limits which
 * secrets it can read. It is never a grant secret: the connector writes
 * those and must not read one, and a grant must never write over the
 * manager's login.
 */
const managerSecretArn = z
  .string()
  .regex(MANAGER_SECRET_ARN_PATTERN)
  .refine((arn) => !secretNameOfArn(arn).startsWith(GRANT_SECRET_PREFIX), {
    message: "managerSecretArn must not name a grant secret",
  });

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
  managerSecretArn,
});

export type Target = z.infer<typeof target>;

export const installContext = z.object({ target });

export type InstallContext = z.infer<typeof installContext>;
