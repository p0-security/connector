// shape copied from services/p0-connector-argocd/src/install/definition.ts
import { z } from "zod";

/**
 * The checks install validation runs, in the order it runs them, by the name
 * a failure reports in `payload.step`. P0 reads these, so the set is closed
 * and the order is fixed: a change to either is a change to the contract.
 */
export const SNOWFLAKE_AI_INSTALL_STEPS = [
  "private_key",
  "sign_in",
  "admin_roles",
  "account_usage",
  "mcp_server",
  "agent_auth_policy",
] as const;

export const snowflakeAiInstallStep = z.enum(SNOWFLAKE_AI_INSTALL_STEPS);

export type SnowflakeAiInstallStep = z.infer<typeof snowflakeAiInstallStep>;

/**
 * What install validation returns once every check has passed. A failed check
 * is thrown, so these are facts about an install that works.
 */
export const installValidation = z.object({
  /** The user and role the connector signed in as. */
  user: z.string().min(1),
  role: z.string().min(1),
});

export type InstallValidation = z.infer<typeof installValidation>;
