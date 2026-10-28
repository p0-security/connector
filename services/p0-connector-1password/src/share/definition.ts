import { z } from "zod";

import { itemId, vaultCredentials } from "../accesses/share/definition.ts";

/**
 * How long a share link lasts: 1Password's own options, shortest first. P0
 * rounds the approved duration to one of them.
 */
export const SHARE_DURATIONS = [
  "OneHour",
  "OneDay",
  "SevenDays",
  "FourteenDays",
  "ThirtyDays",
] as const;

export const shareDuration = z.enum(SHARE_DURATIONS);

export type ShareDuration = z.infer<typeof shareDuration>;

/** What P0 sends to share one item with one person. */
export const shareInput = vaultCredentials.extend({
  itemId,
  /** The requestor's P0 email, the only person the link opens for. */
  email: z.email(),
  expireAfter: shareDuration,
  /** Whether the link opens only once: the account's one-time links setting. */
  oneTimeOnly: z.boolean(),
});

export type ShareInput = z.infer<typeof shareInput>;

export const shareOutput = z.object({
  /** The share link. It opens only for `email`. */
  link: z.string().min(1),
  /**
   * When the link stops opening, estimated as when the connector asked plus
   * `expireAfter`: 1Password doesn't say.
   */
  expiresAt: z.iso.datetime(),
  /**
   * Whether the link opens only once, as the connector asked 1Password. P0
   * checks it matches what it asked for: a connector too old to know the
   * setting would drop it from the input and make a link that opens again.
   */
  oneTimeOnly: z.boolean(),
});

export type ShareOutput = z.infer<typeof shareOutput>;
