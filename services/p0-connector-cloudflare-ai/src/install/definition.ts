import { z } from "zod";

/**
 * The permission groups the install token must hold, by Cloudflare's group
 * id, with the name the dashboard shows (spec section 3).
 */
export const REQUIRED_GROUPS = {
  /** Mint, change and delete grant tokens; list permission groups. */
  accountApiTokensWrite: {
    id: "5bc3f8b21c554832afc660159ab75fa4",
    label: "Account API Tokens Edit on the account",
  },
  /** Map zone names to ids. */
  zoneRead: {
    id: "c8fed203ed3043cba015a93ad1616f1f",
    label: "Zone Read on all zones of the account",
  },
} as const;

/**
 * What install validation returns once every check has passed. A failed
 * check is thrown, with its name in `payload.step`.
 */
export const installValidation = z.object({
  /** Cloudflare's id for the install token. */
  tokenId: z.string().min(1),
  /**
   * The names of the token's groups beyond the required two, sorted. Not
   * empty passes, and P0 shows it as a warning.
   */
  otherGroups: z.array(z.string()),
});

export type InstallValidation = z.infer<typeof installValidation>;
