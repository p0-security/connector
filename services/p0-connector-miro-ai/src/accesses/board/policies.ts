import { ConnectorError, type Logger } from "@p0security/connector-core";

import {
  type BoardMember,
  type MiroClient,
  type MiroUser,
  type Pause,
  SHARING_ROLES,
  isStatus,
} from "../../miro/client.ts";
import { callMiro, connectMiro } from "../../miro/connect.ts";
import {
  type HeldRole,
  highestOf,
  isHeldRole,
  rankOf,
  ranksAtLeast,
} from "../../miro/roles.ts";
import { refusal } from "../../refusals.ts";
import type { BoardRole, RequestContext } from "./definition.ts";
import { checkGrantee, checkTeam } from "./members.ts";

/** How many times a revoke's write is tried when Miro answers 403. */
export const REVOKE_ATTEMPTS = 3;

/** How long a revoke waits before trying a 403'd write again, in seconds. */
export const REVOKE_RETRY_SECONDS = 1;

/** The member a call acts on, and what it acts with. */
export type Target = {
  miro: MiroClient;
  boardId: string;
  memberId: string;
  /** Bound to the request, the board and the member. No email. */
  log: Logger;
  pause?: Pause;
};

/** The member's role on the board, from the members list: `none` when they aren't a direct member. */
const roleOf = (members: BoardMember[], memberId: string): string =>
  members.find(({ id }) => id === memberId)?.role ?? "none";

/** The error for a role Miro reports that the connector doesn't rank. */
const unknownRole = ({ boardId, memberId }: Target, role: string) =>
  new ConnectorError({
    message: `Miro reports the role ${role} for member ${memberId} on board ${boardId}, which the connector doesn't know, so it can't tell which way a change would go. Ask a Miro admin to check the member's role.`,
    payload: { boardId, memberId, role },
    type: "validation_error",
  });

/**
 * The board's members for a grant. A board Miro doesn't have is a
 * `validation_error` that says what to do, since `object_not_found` reaches
 * the requester as a bare "Not found".
 */
const membersForGrant = async ({
  miro,
  boardId,
}: Target): Promise<BoardMember[]> => {
  try {
    return await miro.listBoardMembers(boardId);
  } catch (error) {
    if (!isStatus(error, 404)) throw error;
    throw new ConnectorError({
      message: `Miro has no board ${boardId}, or the connector user can't see it. Check the board's ID, then request access again.`,
      payload: { boardId, status: 404 },
      type: "validation_error",
    });
  }
};

/**
 * Refuses unless the connector user is the board's owner or co-owner, so
 * can share it (spec section 4, grant step 5).
 */
const checkShareable = (
  { boardId, log }: Target,
  members: BoardMember[],
  connectorUserId: string
) => {
  if (SHARING_ROLES.has(roleOf(members, connectorUserId))) return;
  log.info("refused the grant: the connector user can't share the board");
  throw refusal({
    message: `P0 can't share board ${boardId}: its connector user must be the board's owner or co-owner.`,
    payload: { boardId },
    reason: "board_not_shareable",
  });
};

/**
 * Adds the member at `viewer`. Miro refuses a POST at `viewer` (spec V1), so
 * the member is added as `commenter`, then lowered. If the lowering fails,
 * the member is removed again and the grant fails: nobody keeps more than
 * P0 granted.
 */
const addAsViewer = async (target: Target, user: MiroUser) => {
  const { miro, boardId, memberId, log } = target;
  await addMember(target, user, "commenter");
  try {
    await miro.setBoardMemberRole(boardId, memberId, "viewer");
  } catch (error) {
    log.warn(
      "lowering the new member to viewer failed, so they are removed again"
    );
    await miro
      .removeBoardMember(boardId, memberId)
      .catch((removal: unknown) => {
        log.error(
          { removed: false },
          "removing the member after the failed lowering failed too"
        );
        throw new ConnectorError({
          message: `Miro added member ${memberId} to board ${boardId} as commenter, then refused both lowering them to viewer and removing them. Ask a Miro admin to remove them from the board, then request access again.`,
          payload: { boardId, memberId },
          type: "dependency_violation",
          cause: removal,
        });
      });
    throw error;
  }
};

/**
 * Adds the member at `role`, and checks the member Miro added is the one
 * P0 checked. If it isn't, it is removed again and the grant fails.
 */
const addMember = async (
  { miro, boardId, memberId, log }: Target,
  user: MiroUser,
  role: string
) => {
  // The member's own Miro email, which the account check matched to the
  // requester's.
  const email = user.email ?? "";
  const added = await miro.addBoardMember(boardId, { email, role });
  if (added === memberId) return;
  log.warn({ added }, "Miro added another member than the one P0 checked");
  await miro.removeBoardMember(boardId, added);
  throw new ConnectorError({
    message: `Miro added another member than ${memberId} to board ${boardId}, so P0 removed them again. Contact P0 support.`,
    payload: { boardId, memberId },
    type: "unknown",
  });
};

/**
 * Raises the member's role on the board to the request's own, `goal`, when
 * it ranks above the role they hold (spec section 4, grant steps 3 and 4).
 * It never lowers: a member at or above it is left as they are, and the
 * request's record says it changed nothing.
 *
 * An existing member gets a PATCH. A new member gets a POST at the role,
 * except `viewer` ({@link addAsViewer}).
 */
export const grantBoardRole = async (
  target: Target,
  {
    user,
    members,
    goal,
  }: { user: MiroUser; members: BoardMember[]; goal: BoardRole }
): Promise<void> => {
  const { miro, boardId, memberId, log } = target;
  const current = roleOf(members, memberId);
  if (!isHeldRole(current)) throw unknownRole(target, current);
  if (ranksAtLeast(current, goal)) {
    log.info(
      { current, goal },
      "the member's role is already at or above the goal, so nothing changes"
    );
    return;
  }
  if (current !== "none") {
    await miro.setBoardMemberRole(boardId, memberId, goal);
  } else if (goal === "viewer") {
    await addAsViewer(target, user);
  } else {
    await addMember(target, user, goal);
  }
  log.info(
    { from: current, to: goal },
    "raised the member's role on the board"
  );
};

/**
 * The error for a revoke Miro keeps refusing: the connector user has lost
 * the role that lets it change the board's members (spec section 4, revoke
 * step 5). Never reported as success, and its payload says so, so P0 marks
 * the grant **revoke failed**.
 */
const revokeFailed = ({ boardId, memberId, log }: Target, cause: unknown) => {
  log.error(
    { attempts: REVOKE_ATTEMPTS, revokeFailed: true },
    "Miro kept refusing the revoke: the connector user isn't the board's owner or co-owner"
  );
  return new ConnectorError({
    message: `P0 couldn't take back access to Miro board ${boardId}: Miro refused the change ${REVOKE_ATTEMPTS} times. The connector user must be the board's owner or co-owner. Make it co-owner again, then retry the revoke.`,
    payload: { boardId, memberId, missingRole: "coowner", revokeFailed: true },
    type: "insufficient_privileges",
    cause,
  });
};

/**
 * Runs a revoke's write, tried again after a 403, {@link REVOKE_ATTEMPTS}
 * times in all, then fails with {@link revokeFailed}. A 404 means the
 * member is gone, so there is nothing left to take back.
 */
const revokeWrite = async (target: Target, write: () => Promise<void>) => {
  const { log, pause } = target;
  for (let attempt = 1; ; attempt++) {
    try {
      await write();
      return;
    } catch (error) {
      if (isStatus(error, 404)) {
        log.info("the member is no longer on the board");
        return;
      }
      if (!isStatus(error, 403)) throw error;
      if (attempt >= REVOKE_ATTEMPTS) throw revokeFailed(target, error);
      log.info({ attempt }, "Miro refused the revoke, so it is tried again");
      await pause?.(REVOKE_RETRY_SECONDS);
    }
  }
};

/**
 * Lowers the member's role on the board to the highest role that remains:
 * a sibling's in `policies`, or `priorRole` (spec section 4, revoke).
 *
 * - Done when the board or the member is gone.
 * - When the member's role is none P0 could have left there (not the prior
 *   role, the request's own, or a sibling's), someone changed it outside
 *   P0, and it is left alone: **changed outside P0** (revoke step 3).
 * - It never raises: a role lowered during the grant stays lower, and a
 *   sibling whose grant hasn't run yet is raised by that grant, with its
 *   checks (revoke step 2).
 * - The goal `none` removes the member, which takes only their direct role:
 *   team and link access stay (spec V1, assumption 6).
 */
export const revokeBoardRole = async (
  target: Target,
  {
    own,
    policies,
    priorRole,
  }: { own: BoardRole; policies: BoardRole[]; priorRole: HeldRole }
): Promise<void> => {
  const { miro, boardId, memberId, log } = target;
  let members: BoardMember[];
  try {
    members = await miro.listBoardMembers(boardId);
  } catch (error) {
    if (!isStatus(error, 404)) throw error;
    log.info("Miro has no such board, so there is nothing to take back");
    return;
  }
  const current = roleOf(members, memberId);
  if (!isHeldRole(current)) throw unknownRole(target, current);

  const known: HeldRole[] = [priorRole, own, ...policies];
  if (!known.includes(current)) {
    log.warn(
      { changedOutsideP0: true, current },
      "left the member's role alone: it changed outside P0 during the grant"
    );
    return;
  }
  const goal = highestOf([priorRole, ...policies]);
  if ((rankOf(goal) ?? -1) >= (rankOf(current) ?? -1)) {
    log.info(
      { current, goal },
      "left the member's role as it is: it doesn't rank above the goal"
    );
    return;
  }
  if (goal === "none") {
    await revokeWrite(target, () => miro.removeBoardMember(boardId, memberId));
    log.info({ from: current }, "removed the member from the board");
    return;
  }
  await revokeWrite(target, () =>
    miro.setBoardMemberRole(boardId, memberId, goal)
  );
  log.info(
    { from: current, to: goal },
    "lowered the member's role on the board"
  );
};

/**
 * `setPoliciesForUser`, for the board access: works out whether the call
 * grants or revokes, runs a grant's checks, and maps Miro's failures onto
 * the errors P0 shows.
 *
 * A call is a revoke when `operation` says so, or when `held` is false:
 * the request's own role isn't in `policies`. P0 sets `operation` from the
 * request's status, so the call that rolls back a failed grant still says
 * `grant`, and only its policies show it is a revoke. Every other role in
 * `policies` is a sibling request's, on the same member and board.
 *
 * A grant checks, before it writes anything, that the token is still the
 * team's, that the member is still the requester, and that the connector
 * user can share the board. Each refusal is a `validation_error` P0 shows
 * in its own words. A revoke checks only the token's team: taking access
 * away mustn't depend on the member.
 */
export const setBoardPolicies = async ({
  context,
  memberId,
  policies,
  logger,
  pause,
}: {
  context: RequestContext;
  memberId: string;
  policies: BoardRole[];
  logger: Logger;
  pause?: Pause;
}): Promise<void> => {
  const { boardId, email, operation, priorRole, requestId, role, teamId } =
    context;
  const held = policies.includes(role);
  const effectiveOperation =
    operation === "revoke" || !held ? "revoke" : "grant";
  // No email in the bindings: it is only checked, never logged.
  const log = logger.child({
    access: "board",
    boardId,
    effectiveOperation,
    memberId,
    operation,
    requestId,
  });
  if (operation === "grant" && !held) {
    log.warn(
      "the call says grant, but the request's own role isn't in its policies, so it is treated as the rollback of a failed grant"
    );
  }
  if (operation === "revoke" && held) {
    log.warn(
      "the call says revoke, but a sibling request still holds the request's own role, which the revoke leaves in place"
    );
  }

  const miro = await connectMiro(context, log, pause);
  const target: Target = {
    boardId,
    log,
    memberId,
    miro,
    ...(pause === undefined ? {} : { pause }),
  };
  await callMiro(async () => {
    if (effectiveOperation === "revoke") {
      await checkTeam(miro, { operation: "revoke", teamId }, log);
      await revokeBoardRole(target, { own: role, policies, priorRole });
      return;
    }
    const { teamName, userId } = await checkTeam(
      miro,
      { operation: "grant", teamId },
      log
    );
    const user = await checkGrantee(
      miro,
      { email, memberId, teamId, teamName },
      log
    );
    const members = await membersForGrant(target);
    checkShareable(target, members, userId);
    await grantBoardRole(target, { goal: role, members, user });
  });
};
