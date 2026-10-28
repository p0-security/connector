import { z } from "zod";

/**
 * What install validation returns for a tenant once every check has passed.
 * A failed check is thrown with its name in `payload.step`, so these are
 * facts about an install that works, not results to inspect.
 */
export const installValidation = z.object({
  /** The tenant the checks ran against. */
  tenant: z.string(),
  /** The connector's `DOMAIN_ALLOW_PATTERN` as deployed, for the install to display. */
  allowedDomains: z.string(),
});

export type InstallValidation = z.infer<typeof installValidation>;
