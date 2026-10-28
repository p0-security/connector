import { z } from "zod";

/**
 * The display name of the service principal P0 creates for one grant:
 * `p0-agent-<request id>`. P0 chooses it. The connector only checks it, and
 * acts on no service principal outside this namespace.
 */
export const AGENT_NAME_PATTERN = /^p0-agent-[A-Za-z0-9_-]{1,200}$/;

/** Parses an agent principal's display name. Both `UserBody` and `UserId`. */
export const agentName = z.string().regex(AGENT_NAME_PATTERN);
