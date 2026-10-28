import { z } from "zod";

/**
 * Which kind of access token the connector holds: `service` for a service
 * token, `personal` for a member's own token.
 */
export const TOKEN_KINDS = ["service", "personal"] as const;

export type TokenKind = (typeof TOKEN_KINDS)[number];

/**
 * What install validation returns for an account once every check has
 * passed. A failed check is thrown, with its name in `payload.step`, so these
 * are facts about an install that works, not results to inspect.
 */
export const installValidation = z.object({
  /** LaunchDarkly's id for the account the token belongs to. */
  accountId: z.string().min(1),
  /**
   * The connector's `DOMAIN_ALLOW_PATTERN`, less the whitespace around it,
   * for P0 to show. P0 never sends it back: the connector reads its own.
   */
  domainPattern: z.string().min(1),
  tokenKind: z.enum(TOKEN_KINDS),
  /**
   * The member a personal token acts as, which the connector never changes.
   * `null` for a service token.
   */
  tokenOwnerMemberId: z.string().min(1).nullable(),
});

export type InstallValidation = z.infer<typeof installValidation>;
