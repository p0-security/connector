import { z } from "zod";

/**
 * What install validation returns for an account once every check has passed.
 * A failed check is thrown, with its `payload.step`, so these are facts about
 * an install that works, not results to inspect.
 */
export const installValidation = z.object({
  /** How many vaults the service account can see: the vaults people can
   * request items from. */
  vaultCount: z.number().int().positive(),
  /**
   * Whether the `sharing` check read the account's sharing policy. 1Password
   * reads it through an item, so the check is skipped when no vault the
   * service account sees has an active item.
   */
  sharingChecked: z.boolean(),
  /** The connector's `DOMAIN_ALLOW_PATTERN` as deployed, for the install to display. */
  allowedDomains: z.string(),
});
export type InstallValidation = z.infer<typeof installValidation>;
