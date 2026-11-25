// shape copied from services/p0-connector-snowflake-ai/src/install/definition.ts
import { z } from "zod";

import { pgClientParams } from "../accesses/common/definition.ts";

/**
 * One target: a PostgreSQL instance or cluster P0 manages, the database the
 * manager connects to, and the secret that holds the manager's login.
 */
export const target = pgClientParams.pick({
  host: true,
  port: true,
  database: true,
  managerSecret: true,
});

export type Target = z.infer<typeof target>;

export const installContext = z.object({ target });

export type InstallContext = z.infer<typeof installContext>;

/**
 * The checks install validation is to run, in the order it runs them, by the
 * name a failure reports in `payload.step`. P0 is to read these, so the set is
 * closed and the order is fixed: a change to either is a change to the
 * contract. The README says what each one checks.
 */
export const PG_VAULTED_INSTALL_STEPS = [
  "manager_secret",
  "sign_in",
  "create_role",
  "signal_backend",
  "reassign_owned",
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
