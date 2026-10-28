import { ConnectorError } from "@p0security/connector-core";

import type { HarborRole } from "../accesses/project-role/definition.ts";

/**
 * Harbor's project roles, lowest first. Each holds every permission of the
 * ones below it (Harbor's `rolePower`), so a role's place here is its rank.
 */
export const ROLES_BY_RANK = [
  "limitedGuest",
  "guest",
  "developer",
  "maintainer",
  "projectAdmin",
] as const satisfies readonly HarborRole[];

/**
 * Harbor's id for each role (`src/common/const.go`, the same at v2.12.0 and
 * v2.14.0). The ids are not in rank order: never compare roles by id.
 */
const ROLE_IDS: Readonly<Record<HarborRole, number>> = {
  projectAdmin: 1,
  developer: 2,
  guest: 3,
  maintainer: 4,
  limitedGuest: 5,
};

/** Harbor's id for `role`, which member writes send as `role_id`. */
export const roleId = (role: HarborRole): number => ROLE_IDS[role];

/**
 * The role a member row's `role_id` names, or `undefined` for an id that
 * isn't one of Harbor's five. Harbor stores a `role_id` a `PUT` sends without
 * checking it, so a row can hold any id.
 */
export const roleOf = (id: number): HarborRole | undefined =>
  ROLES_BY_RANK.find((role) => ROLE_IDS[role] === id);

/** `role`'s place in {@link ROLES_BY_RANK}: a higher number holds more. */
export const rankOf = (role: HarborRole): number => ROLES_BY_RANK.indexOf(role);

/** Whether `role` holds less than `other`. */
export const ranksBelow = (role: HarborRole, other: HarborRole): boolean =>
  rankOf(role) < rankOf(other);

/**
 * The error for a member row whose `role_id` isn't one of Harbor's five. P0
 * can neither record nor restore a role it doesn't know, and reading the row
 * as "no role" would let a revoke remove the member. No `reason`: P0 passes
 * the message through (A17b).
 *
 * Harbor's member list is believed to leave such a row out (it inner-joins
 * the role table: INT-265's research, read from source, not checked live),
 * so this is defence for a Harbor that lists one, such as a later version
 * with a sixth role.
 *
 * Reading a role or granting one, it is a `validation_error`, which the
 * requester sees with this message at request time. At a revoke it is a
 * `dependency_violation`: nobody is waiting on a revoke, P0 turns it into a
 * state error in these words, and the revoke stays errored where an admin
 * will see it.
 */
export const unknownRole = (
  row: { roleId: number },
  { host, project, userId }: { host: string; project: string; userId: string },
  during: "grant" | "read" | "revoke"
) =>
  new ConnectorError({
    type: during === "revoke" ? "dependency_violation" : "validation_error",
    message: `Harbor user ${userId} holds role id ${row.roleId} on project ${project} on ${host}, which isn't one of Harbor's project roles${
      during === "revoke" ? ", so P0 can't put their prior role back" : ""
    }. Ask a Harbor admin to set the user's role on the project's Members tab${
      during === "read" ? "" : `, then retry the ${during}`
    }.`,
    payload: { host, project, userId, roleId: row.roleId },
  });

/** The role a member row holds, or {@link unknownRole} thrown. */
export const knownRoleOf = (
  row: { roleId: number },
  where: { host: string; project: string; userId: string },
  during: "grant" | "read" = "read"
): HarborRole => {
  const role = roleOf(row.roleId);
  if (role !== undefined) return role;
  throw unknownRole(row, where, during);
};
