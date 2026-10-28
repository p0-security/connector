/**
 * LaunchDarkly's base roles, weakest first: `no_access < reader < writer <
 * admin < owner`. A `base-role` grant only raises a member along this rank,
 * and a revoke only lowers. The connector never writes over `owner`, or over
 * a role outside the rank, which is one it doesn't know.
 */
export const BASE_ROLES_BY_RANK = [
  "no_access",
  "reader",
  "writer",
  "admin",
  "owner",
] as const;

export type RankedRole = (typeof BASE_ROLES_BY_RANK)[number];

/** The role's place in the rank, from 0, or `undefined` outside it. */
export const rankOf = (role: string): number | undefined => {
  const rank = BASE_ROLES_BY_RANK.findIndex((ranked) => ranked === role);
  return rank < 0 ? undefined : rank;
};

/** Whether `role` is in the rank and ranks at or above `floor`. */
export const ranksAtLeast = (role: string, floor: RankedRole): boolean =>
  (rankOf(role) ?? -1) >= BASE_ROLES_BY_RANK.indexOf(floor);

/** Whether `role` ranks below `other`. Never for an `other` outside the rank. */
export const ranksBelow = (role: RankedRole, other: string): boolean => {
  const rank = rankOf(other);
  return rank !== undefined && BASE_ROLES_BY_RANK.indexOf(role) < rank;
};

/** The highest of one or more roles. */
export const highestOf = <Role extends RankedRole>([
  first,
  ...others
]: readonly [Role, ...Role[]]): Role =>
  others.reduce(
    (highest, role) =>
      BASE_ROLES_BY_RANK.indexOf(role) > BASE_ROLES_BY_RANK.indexOf(highest)
        ? role
        : highest,
    first
  );
