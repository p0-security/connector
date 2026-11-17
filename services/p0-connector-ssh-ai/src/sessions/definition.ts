import { z } from "zod";

import { instance } from "../context.ts";

/**
 * A gateway session's id. The gateway assumes the agent's role with this id
 * as the role session name, so the schema holds it to what STS allows
 * there. That set has no `/`, so the id can only match the last part of an
 * owner's ARN.
 */
const gatewaySessionId = z.string().regex(/^[\w+=,.@-]{2,64}$/);

export const endSessionsInput = z.object({
  instance,
  sessionId: gatewaySessionId,
  /** The P0 request this belongs to. It only goes into the log lines. */
  requestId: z.string().min(1).optional(),
});

export type EndSessionsInput = z.infer<typeof endSessionsInput>;

/** What ending a gateway session's SSM sessions on one instance did. */
export type EndSessionsResult = {
  /** The open SSM sessions the gateway session owned on the instance. */
  matched: number;
  /** How many of those SSM refused to end. */
  failed: number;
};
