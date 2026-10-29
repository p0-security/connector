import { z } from "zod";

import { AGENT_USER_PATTERN, isIdentifier, isUserName } from "./sql.ts";

export const TARGET_TYPES = ["provisioned", "serverless"] as const;

export type TargetType = (typeof TARGET_TYPES)[number];

/**
 * A provisioned cluster identifier or a Serverless workgroup name: lower-case
 * letters, digits and hyphens, starting with a letter.
 */
const targetName = z.string().regex(/^[a-z][a-z0-9-]{0,63}$/);

// Closed, so that a request context can't send the connector's calls to an
// endpoint outside AWS's regional ones.
const region = z.string().regex(/^[a-z]{2}(-[a-z]+)+-\d{1,2}$/);

const identifier = z.string().refine(isIdentifier, "Invalid identifier");

const userName = z.string().refine(isUserName, "Invalid user name");

/**
 * One installed provisioned cluster or Serverless workgroup. The connector
 * reaches it only through the Data API, in its region, as its own execution
 * role's database user.
 */
export const installContext = z.object({
  target: z.object({ type: z.enum(TARGET_TYPES), name: targetName }),
  region,
  /** The database the connector's admin statements connect to. */
  database: identifier,
  /** Who takes over what an agent created when it is revoked. When absent,
   * the connector's own user does. */
  objectOwner: userName.optional(),
});

export type InstallContext = z.infer<typeof installContext>;

export type Target = InstallContext["target"];

/** The agent's database user, `IAMR:p0-agent-<id>`. */
export const agentUser = z.string().regex(AGENT_USER_PATTERN);

export const requestContext = installContext.extend({
  requestId: z.string().min(1),
});

export type RequestContext = z.infer<typeof requestContext>;

// copied from services/p0-connector-snowflake-ai/src/context.ts, without the warehouse
export const LISTER_TYPES = ["role", "object"] as const;

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
