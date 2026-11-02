import { ConnectorError, type Logger } from "@p0security/connector-core";

import type { MiroClient, MiroUser, TokenInfo } from "../../miro/client.ts";
import { refusal } from "../../refusals.ts";

/** Whether two emails are the same, ignoring case. */
export const isSameEmail = (miroEmail: string | undefined, email: string) =>
  miroEmail !== undefined && miroEmail.toLowerCase() === email.toLowerCase();

/** Miro's `state` for someone invited to the team without a Miro account. */
const NOT_REGISTERED = "not_registered";

/** The refusal for a requester who isn't a member of the team. */
export const notInTeam = (teamName: string) =>
  refusal({
    message: `Your Miro user isn't in team ${teamName}. Ask a Miro admin to add you, then request again.`,
    payload: { team: teamName },
    reason: "not_in_team",
  });

/** The refusal for a requester whose team invite is still pending. */
export const pendingInvite = (teamName: string) =>
  refusal({
    message: `You have a pending invite to Miro team ${teamName}. Accept it and create your Miro account, then request again.`,
    payload: { team: teamName },
    reason: "pending_invite",
  });

/** The refusal for a member whose Miro account isn't the one P0 recorded. */
export const accountChanged = (memberId: string) =>
  refusal({
    message:
      "Your Miro account changed after you requested access. Request access again.",
    payload: { changed: "account", memberId },
    reason: "member_changed",
  });

/**
 * The access token's team, which must be `teamId`: with another team's
 * token, a lookup or a grant would act on that team instead.
 *
 * A lookup or a grant refuses with `member_changed` (`changed: "team"`). A
 * revoke fails with `insufficient_privileges` instead: P0 treats a refusal
 * as done, and the access is still there to take back once the secret holds
 * the right token.
 */
export const checkTeam = async (
  miro: MiroClient,
  { teamId, operation }: { teamId: string; operation: "grant" | "revoke" },
  log: Logger
): Promise<TokenInfo> => {
  const info = await miro.fetchTokenInfo();
  if (info.teamId === teamId) return info;
  log.warn({ changed: "team" }, "the access token belongs to another team");
  if (operation === "revoke") {
    throw new ConnectorError({
      message: `The Miro connector's access token belongs to another team than team ${teamId}, where P0 granted access, so P0 took nothing back. Put the team's own token in its secret, then retry the revoke.`,
      payload: { teamId },
      type: "insufficient_privileges",
    });
  }
  throw refusal({
    message: `The Miro connector's access token belongs to another team than team ${teamId}. Check the token in the team's secret, then request access again.`,
    payload: { changed: "team", teamId },
    reason: "member_changed",
  });
};

/**
 * The team's one member with `email`, ignoring case (spec section 4, grant
 * step 1). Miro's team list carries user ids and no email, so each member
 * is read in turn until one matches.
 *
 * Refuses with `not_in_team` when none has it: P0 never invites, so it never
 * spends a seat. Refuses with `pending_invite` when the match hasn't created
 * a Miro account yet, which keeps P0's grants away from pending invites that
 * a revoke's DELETE could cancel (spec V1, assumption 10).
 */
export const findTeamMember = async (
  miro: MiroClient,
  {
    email,
    teamId,
    teamName,
  }: { email: string; teamId: string; teamName: string },
  log: Logger
): Promise<MiroUser> => {
  for (const id of await miro.listTeamMemberIds(teamId)) {
    const user = await miro.fetchUser(id);
    if (user === undefined || !isSameEmail(user.email, email)) continue;
    if (user.state === NOT_REGISTERED) {
      log.info({ memberId: id }, "refused: the requester's invite is pending");
      throw pendingInvite(teamName);
    }
    return user;
  }
  log.info("refused: no member of the team has the requester's email");
  throw notInTeam(teamName);
};

/**
 * Checks, before a grant writes anything, that `memberId` is still the
 * requester: a member of the team, with the requester's email, who has
 * created a Miro account (spec section 4, the account check). Returns the
 * member's Miro user.
 */
export const checkGrantee = async (
  miro: MiroClient,
  {
    email,
    memberId,
    teamId,
    teamName,
  }: { email: string; memberId: string; teamId: string; teamName: string },
  log: Logger
): Promise<MiroUser> => {
  const memberIds = await miro.listTeamMemberIds(teamId);
  if (!memberIds.includes(memberId)) {
    log.info("refused the grant: the member isn't in the team");
    throw notInTeam(teamName);
  }
  const user = await miro.fetchUser(memberId);
  if (user === undefined || !isSameEmail(user.email, email)) {
    log.info("refused the grant: the member's email isn't the requester's");
    throw accountChanged(memberId);
  }
  if (user.state === NOT_REGISTERED) {
    log.info("refused the grant: the requester's invite is pending");
    throw pendingInvite(teamName);
  }
  return user;
};
