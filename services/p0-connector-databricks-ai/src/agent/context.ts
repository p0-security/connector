import { z } from "zod";

import { accountContext, workspaceId } from "../databricks/context.ts";

/**
 * The subject the gateway signs into the agent's token for one session on
 * one MCP server: `mcps/<server id>/<hash>`.
 */
const FEDERATION_SUBJECT = /^mcps\/[^/]+\/[^/]+$/;

/**
 * What the agent's federation policy trusts. The gateway exchanges a token
 * it signs for the agent principal's Databricks token, and Databricks takes
 * it only from this issuer, for this subject.
 */
export const federation = z.object({
  /** P0's auth server, which signs the gateway's tokens. */
  issuer: z.url({ protocol: /^https$/ }),
  /** The requesting session's subject on the server it requested through. */
  subject: z.string().regex(FEDERATION_SUBJECT),
});

/**
 * The request context the agent principal's lifecycle reads. On top of the
 * account context, whose `applicationId` is P0's own principal, it names the
 * workspace the grant is in, the agent principal stage created, and what its
 * federation policy trusts.
 */
export const agentContext = accountContext.extend({
  workspaceId,
  /** The agent principal's `applicationId`, as `principal.stage` returned it. */
  agentApplicationId: z.guid(),
  federation,
});

export type AgentContext = z.infer<typeof agentContext>;
