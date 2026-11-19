// shape copied from services/p0-connector-snowflake-ai/src/install/definition.ts
import { z } from "zod";

/**
 * The checks install validation runs, in the order it runs them, by the name
 * a failure reports in `payload.step`. P0 reads these, so the set is closed
 * and the order is fixed: a change to either is a change to the contract.
 *
 * - `manager_mapping`: the target's host is in the connector's manager
 *   mapping.
 * - `sign_in`: the manager authenticates to the target.
 * - `create_role`: the manager can create roles (`CREATEROLE`).
 * - `signal_backend`: the manager can end other logins' sessions
 *   (`pg_signal_backend`).
 */
export const PG_VAULTED_INSTALL_STEPS = [
  "manager_mapping",
  "sign_in",
  "create_role",
  "signal_backend",
] as const;

export const pgVaultedInstallStep = z.enum(PG_VAULTED_INSTALL_STEPS);

export type PgVaultedInstallStep = z.infer<typeof pgVaultedInstallStep>;

/**
 * What install validation returns once every check has passed. A failed check
 * is thrown, so these are facts about an install that works.
 */
export const installValidation = z.object({
  /** The roles the manager holds `ADMIN OPTION` on: the roles it can hand
   * out, so the only ones a grant can be approved for. */
  grantableRoles: z.array(z.string().min(1)),
});

export type InstallValidation = z.infer<typeof installValidation>;
