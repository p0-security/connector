import { z } from "zod";

import { isIdentifierPart, isObjectName } from "./sql.ts";

/**
 * The minted user's name, which is also its wrapper role's name:
 * `P0_AGENT_<request id>`. P0 chooses it; the connector only checks it, and
 * acts on no user or role outside this namespace.
 */
export const AGENT_NAME_PATTERN = /^P0_AGENT_[A-Z0-9_]{1,200}$/;

export const agentName = z.string().regex(AGENT_NAME_PATTERN);

const identifier = z.string().refine(isIdentifierPart, "Invalid identifier");

const objectName = z.string().refine(isObjectName, "Invalid object name");

/** `DB.SCHEMA.NAME`, for a schema-level object such as the MCP server. */
const schemaObjectName = objectName.refine(
  (value) => value.split(".").length === 3,
  "Expected DB.SCHEMA.NAME"
);

// The SDK signs in at `<account>.snowflakecomputing.com`. The pattern is
// closed so that a request context cannot send the connector's key-pair JWT
// to another host.
const account = z.string().regex(/^[A-Za-z0-9_-]+$/);

// copy of the `adminKeys` union in services/p0-connector-datadog-ai/src/accesses/permission/definition.ts
/**
 * Where the connector's private key and the agents' tokens are stored: AWS
 * Secrets Manager (the connector on Lambda) or Google Secret Manager (on Cloud
 * Run). The private key's value is an unencrypted PKCS8 PEM.
 */
const secrets = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    region: z.string().min(1),
    privateKeySecretId: z.string().min(1),
  }),
  z.object({
    manager: z.literal("gcp"),
    projectId: z.string().min(1),
    privateKeySecretId: z.string().min(1),
  }),
]);

/**
 * One installed Snowflake account. P0 holds the fixed object names the install
 * SQL and Terraform create, and sends them here, so the connector has no
 * names of its own.
 */
export const installContext = z.object({
  account,
  secrets,
  /** The connector's `TYPE = SERVICE` user, its role, and the small warehouse
   * it reads `ACCOUNT_USAGE` with. */
  connector: z.object({
    user: identifier,
    role: identifier,
    warehouse: identifier,
  }),
  /** The install's managed MCP server object. */
  mcpServer: schemaObjectName,
  /** The install's authentication policy for agent users: token sign-in
   * only, and tokens that work without a network policy. */
  agentAuthPolicy: schemaObjectName,
});

export type InstallContext = z.infer<typeof installContext>;

/**
 * The grant's token secret, under the token prefix the connector's IAM grants
 * it, so it can never name another secret: `p0/access-token/snowflake-ai/…`
 * as is in AWS, and with each `/` written as `_` in GCP.
 */
const SECRET_NAME_PATTERNS = {
  aws: /^p0\/access-token\/snowflake-ai\/[A-Za-z0-9-]{1,200}\/[A-Za-z0-9_-]{1,200}$/,
  gcp: /^p0_access-token_snowflake-ai_[A-Za-z0-9_-]{1,200}$/,
} as const;

const secretName = z.string().min(1);

/** The longest `COMMENT` the connector writes. */
const MAX_COMMENT_LENGTH = 1000;

const requestFields = installContext.extend({
  requestId: z.string().min(1),
  /** The warehouse granted to the agent and made its default. The agent can
   * also use any warehouse PUBLIC can, and for role access any the granted
   * roles can. */
  warehouse: identifier,
  /** The grant's length in whole days. Raised to 1, never refused: revoke
   * parses this context too, and must not fail on a grant that has run out. */
  daysToExpiry: z
    .number()
    .int()
    .transform((days) => Math.max(1, days)),
  /** Who asked, for which agent and request: written to the user's and the
   * token's `COMMENT`. Truncated, never refused, for the same reason. */
  comment: z.string().transform((text) => text.slice(0, MAX_COMMENT_LENGTH)),
  /** The secret P0 names for the grant's token. The connector writes the
   * token to it and can't read it back. */
  secretName,
});

export const requestContext = requestFields
  .refine(
    (context) =>
      SECRET_NAME_PATTERNS[context.secrets.manager].test(context.secretName),
    {
      message:
        "secretName must be under the token prefix of its secret manager",
      path: ["secretName"],
    }
  )
  .refine(
    (context) => context.secretName !== context.secrets.privateKeySecretId,
    {
      message: "secretName must not be the private key secret",
      path: ["secretName"],
    }
  );

export type RequestContext = z.infer<typeof requestContext>;

export const LISTER_TYPES = ["role", "warehouse", "object"] as const;

export const listerQuery = z.object({
  type: z.enum(LISTER_TYPES),
  context: installContext,
});

export type ListerQuery = z.infer<typeof listerQuery>;

export const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

export type ListerResponse = z.infer<typeof listerResponse>;
