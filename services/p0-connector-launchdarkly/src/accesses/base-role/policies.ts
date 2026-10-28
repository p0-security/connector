import { ConnectorError } from "@p0security/connector-core";

import type { MemberState } from "../../launchdarkly/client.ts";
import {
  highestOf,
  rankOf,
  ranksAtLeast,
  ranksBelow,
} from "../../launchdarkly/roles.ts";
import { refusal } from "../../refusals.ts";
import {
  type Target,
  confirmGrant,
  memberForRevoke,
} from "../common/policies.ts";
import type { BaseRole, PriorBaseRole } from "./definition.ts";

/**
 * Sets the member's base role from `from` to `to`. The `test` pins the role
 * the connector read, so a change made since, to `owner` among them, fails
 * the write instead of being written over.
 */
const setRole = (
  { launchDarkly, memberId }: Target,
  { from, to }: { from: string; to: string }
) =>
  launchDarkly.patchMember(memberId, [
    { op: "test", path: "/role", value: from },
    { op: "replace", path: "/role", value: to },
  ]);

/**
 * Raises the member's base role to the request's own role, `goal`, when it ranks
 * above the role they hold. It never lowers: a member at or above it, with
 * a higher role a granted sibling holds or `owner`, is left as they are.
 * A sibling's role in `policies` is its own grant's to write: a sibling
 * that is only staged may never be granted, and nothing would lower it.
 *
 * Refused, before any write:
 * - For a member with custom roles assigned directly, since LaunchDarkly
 *   ignores the base role of a member with any (`base_role_ignored`).
 * - For a base role outside the rank, which the connector can't compare.
 */
export const grantBaseRole = async (
  target: Target,
  member: MemberState,
  goal: BaseRole
): Promise<void> => {
  const { host, memberId, log } = target;
  if (member.customRoleIds.length > 0) {
    log.info(
      "refused the grant: the member has custom roles, which LaunchDarkly ranks over the base role"
    );
    throw refusal({
      message: `LaunchDarkly member ${memberId} on ${host} has custom roles, so LaunchDarkly ignores their base role, and raising it would change nothing. Ask a LaunchDarkly admin to remove the member's custom roles first.`,
      payload: { host, memberId },
      reason: "base_role_ignored",
    });
  }
  const current = member.role;
  if (rankOf(current) === undefined) {
    throw new ConnectorError({
      message: `LaunchDarkly member ${memberId} on ${host} has the base role ${current}, which the connector doesn't know, so it can't tell whether ${goal} would raise it. Ask a LaunchDarkly admin to check the member's role, then request access again.`,
      payload: { host, memberId, role: current },
      type: "validation_error",
    });
  }
  if (ranksAtLeast(current, goal)) {
    log.info(
      { current, goal },
      "the member's base role is already at or above the goal"
    );
    return;
  }
  await setRole(target, { from: current, to: goal });
  log.info({ from: current, to: goal }, "raised the member's base role");
  await confirmGrant(target, {
    visible: (now) => ranksAtLeast(now.role, goal),
    what: `the base role ${goal}`,
  });
};

/**
 * Lowers the member's base role to the highest role left in `policies`, or
 * to `priorRole` when none is, when that ranks below the role they hold. It
 * never raises: a sibling request whose grant hasn't run yet is raised by
 * that grant, with its checks. It never writes over `owner`, which P0 never
 * grants, and fails on a role outside the rank, rather than guessing which
 * way the change would go.
 *
 * Done when LaunchDarkly no longer has the member.
 */
export const revokeBaseRole = async (
  target: Target,
  policies: BaseRole[],
  priorRole: PriorBaseRole
): Promise<void> => {
  const { host, memberId, log } = target;
  const member = await memberForRevoke(target);
  if (member === undefined) return;
  const [remaining, ...others] = policies;
  const goal: PriorBaseRole =
    remaining === undefined ? priorRole : highestOf([remaining, ...others]);
  const current = member.role;
  if (current === "owner") {
    log.warn(
      "left the member as they are: they are an owner, which the connector never writes over"
    );
    return;
  }
  if (rankOf(current) === undefined) {
    throw new ConnectorError({
      message: `LaunchDarkly member ${memberId} on ${host} has the base role ${current}, which the connector doesn't know, so P0 can't tell whether ${goal} would lower it, and left it. Ask a LaunchDarkly admin to set the member's role, then retry the revoke.`,
      payload: { host, memberId, role: current },
      type: "dependency_violation",
    });
  }
  if (!ranksBelow(goal, current)) {
    log.info(
      { current, goal },
      "left the member's base role as it is: it doesn't rank above the goal"
    );
    return;
  }
  await setRole(target, { from: current, to: goal });
  log.info({ from: current, to: goal }, "lowered the member's base role");
};
