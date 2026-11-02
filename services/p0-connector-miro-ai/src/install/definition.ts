import { z } from "zod";

/**
 * The scopes the connector user's app must grant its token: reading and
 * sharing boards, and reading the team's members (spec section 3). A token
 * keeps the scopes it was issued with, so adding one takes a reinstall.
 */
export const REQUIRED_SCOPES = [
  "boards:read",
  "boards:write",
  "team:read",
] as const;

/**
 * What install validation returns for a team once every check has passed.
 * A failed check is thrown, with its name in `payload.step`, so these are
 * facts about an install that works, not results to inspect.
 */
export const installValidation = z.object({
  /** Miro's id for the team the token belongs to. */
  teamId: z.string().min(1),
  /**
   * How many of the team's boards the connector user owns or co-owns, so
   * can share. Zero passes, and P0 shows it as a warning: nothing can be
   * requested until the connector user is made co-owner of a board.
   */
  shareableBoards: z.number().int().nonnegative(),
});

export type InstallValidation = z.infer<typeof installValidation>;
