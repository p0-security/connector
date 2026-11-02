/**
 * Every board role Miro reports on a member, weakest first. Each holds every
 * permission of the ones before it, so the order is the rank: a grant only
 * raises a member's role, and a revoke only lowers it.
 */
export const BOARD_ROLES_BY_RANK = [
  "viewer",
  "commenter",
  "editor",
  "coowner",
  "owner",
] as const;

export type BoardMemberRole = (typeof BOARD_ROLES_BY_RANK)[number];

/**
 * A member's role on a board, or `none` for someone who isn't a direct
 * member. Someone who reaches the board only through team or link access
 * reads as `none`: the members list doesn't show them (spec V1).
 */
export type HeldRole = BoardMemberRole | "none";

/** The rank of `role`, `none` below every role, or `undefined` for a role Miro may add that the connector doesn't know. */
export const rankOf = (role: string): number | undefined => {
  if (role === "none") return -1;
  const rank = (BOARD_ROLES_BY_RANK as readonly string[]).indexOf(role);
  return rank === -1 ? undefined : rank;
};

/** Whether `role` is one the connector ranks. */
export const isHeldRole = (role: string): role is HeldRole =>
  rankOf(role) !== undefined;

/** Whether `role` ranks at or above `goal`. */
export const ranksAtLeast = (role: HeldRole, goal: HeldRole): boolean =>
  (rankOf(role) ?? -1) >= (rankOf(goal) ?? -1);

/** The highest of `roles`, or `none` when there are none. */
export const highestOf = (roles: readonly HeldRole[]): HeldRole =>
  roles.reduce<HeldRole>(
    (highest, role) => (ranksAtLeast(highest, role) ? highest : role),
    "none"
  );
