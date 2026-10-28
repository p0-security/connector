import { z } from "zod";

/**
 * What install validation returns for an `instance` once every check has
 * passed. A failed check is thrown, so these are facts about an install that
 * works, not results to inspect.
 */
export const installValidation = z.object({
  /** Harbor's version as the instance reports it, such as `v2.14.0-44a74424`. */
  harborVersion: z.string().min(1),
  /**
   * Harbor's `auth_mode`, which is `oidc_auth`: the connector refuses every
   * other mode. A string, not a literal, so supporting another mode changes
   * the connector and not this schema.
   */
  authMode: z.string().min(1),
  /** The connector's `ALLOWED_EMAIL_DOMAIN_PATTERN` as it is set, which P0 never stores or sends. */
  allowedEmailDomainPattern: z.string().min(1),
});

export type InstallValidation = z.infer<typeof installValidation>;
