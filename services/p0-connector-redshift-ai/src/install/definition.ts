// shape copied from services/p0-connector-snowflake-ai/src/install/definition.ts
import { z } from "zod";

/**
 * The checks install validation runs, in the order it runs them, by the name
 * a failure reports in `payload.step`. P0 reads these, so the set is closed
 * and the order is fixed: a change to either is a change to the contract.
 */
export const REDSHIFT_AI_INSTALL_STEPS = [
  "target",
  "sign_in",
  "admin_roles",
  "object_owner",
] as const;

export const redshiftAiInstallStep = z.enum(REDSHIFT_AI_INSTALL_STEPS);

export type RedshiftAiInstallStep = z.infer<typeof redshiftAiInstallStep>;

/**
 * What the connector found that works but needs the customer's attention.
 * P0 shows each one; none fails the install.
 */
export type InstallWarning =
  /** The connector's user can't grant any object in the install's database:
   * it owns none and holds `WITH GRANT OPTION` on none. Objects access then
   * has nothing to offer. */
  | { check: "grantable_objects"; database: string }
  /** PUBLIC can still create in this database's `public` schema, so an
   * agent can create tables there with no grant. */
  | { check: "public_create"; database: string };

/**
 * What install validation returns once every check has passed. A failed
 * check is thrown, so these are facts about an install that works.
 */
export type InstallValidation = {
  /** The cluster's or workgroup's ARN. */
  arn: string;
  /** The database user the connector signed in as. */
  user: string;
  warnings: InstallWarning[];
};
