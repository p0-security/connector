import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector";

import type { TeamRole } from "../../github/api.ts";
import {
  type ConnectGitHub,
  type GitHubClient,
  connectGitHub,
} from "../../github/client.ts";
import {
  type GitHubTarget,
  TeamNotFoundError,
  callGitHub,
  toConnectorError,
} from "../../github/errors.ts";
import {
  listUsers,
  newUserPrimitives,
  onlyPolicy,
  refuseNonMember,
} from "../common/handler.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

/** The team is acted on by `teamId`. `team` is the slug it has now, for messages. */
type Target = { org: string; team: string; teamId: string; login: string };

/** A removal's target, whose team may be gone, and then has no slug. */
type RemovalTarget = Omit<Target, "team"> & { team: string | null };

const notOrgMember = ({ org, team, teamId, login }: Target) =>
  new ConnectorError({
    type: "validation_error",
    message: `${login} isn't a member of ${org}, so P0 can't add them to ${team}. Add them to the org first.`,
    payload: { reason: "not_org_member", org, team, teamId, login },
  });

// A `validation_error`, because that is the type whose message P0 shows. A
// retried grant refuses the non-member up front, so it never comes back to
// this membership.
const membershipPending = ({ org, team, teamId, login }: Target) =>
  new ConnectorError({
    type: "validation_error",
    message: `${login} isn't a member of ${org}, so P0 can't add them to ${team}. GitHub left their membership of ${team} pending instead, and P0 couldn't remove it. Remove ${login} from ${team} in the team's settings.`,
    payload: { reason: "membership_pending", org, team, teamId, login },
  });

/**
 * Takes back a membership that GitHub left pending, then refuses it.
 *
 * {@link setMembership} checks that the user is in the org before the `PUT`,
 * so GitHub only leaves one pending when they leave the org in between.
 * Removing the membership is all P0 does: it never looks at the org's
 * invitations.
 */
const takeBackPendingMembership = async (
  github: GitHubClient,
  log: Logger,
  target: Target
): Promise<never> => {
  log.warn(
    "GitHub left a non-member's team membership pending, so P0 removes it"
  );
  await github
    .removeTeamMembership({ teamId: target.teamId, login: target.login })
    .catch((error: unknown) => {
      log.warn({ error }, "couldn't remove the pending team membership");
      throw membershipPending(target);
    });
  throw notOrgMember(target);
};

/**
 * Sets `login`'s membership of the team to `role`, for an active org member
 * only.
 *
 * GitHub would take the `PUT` for a non-member too, and invite them to the
 * org. P0 never invites anyone, so membership of the org is checked first
 * ({@link refuseNonMember}), and a `PUT` that GitHub still leaves pending is
 * taken back.
 */
const setMembership = async (
  github: GitHubClient,
  log: Logger,
  target: Target,
  role: TeamRole
) => {
  await refuseNonMember(github, log, {
    login: target.login,
    grants: "a team membership",
    notOrgMember: () => notOrgMember(target),
  });
  const { pending } = await github.putTeamMembership({
    teamId: target.teamId,
    login: target.login,
    role,
  });
  if (pending) await takeBackPendingMembership(github, log, target);
  log.info("set the team membership");
};

/**
 * Takes `login` off the team, org member or not. Running it again changes
 * nothing. A team that's gone has no members, so there's nothing to take them
 * off.
 */
const removeMembership = async (
  github: GitHubClient,
  log: Logger,
  target: RemovalTarget
) => {
  if (target.team === null) {
    log.info(
      "the team doesn't exist any more, so there's no membership to remove"
    );
  } else {
    await github.removeTeamMembership({
      teamId: target.teamId,
      login: target.login,
    });
    log.info("removed the team membership");
  }
};

/**
 * The GitHub `team` access: membership of one team, granted just
 * in time and restored at expiry.
 *
 * Like the `role` access, the "user" is an org member's login, only
 * `setPoliciesForUser` changes anything in GitHub, and every call acts as the
 * customer's own GitHub App.
 *
 * Exported separately from {@link router} so the primitives can be driven
 * against a {@link GitHubClient} double.
 */
export const newTeamPrimitives = (
  logger: Logger,
  connect: ConnectGitHub
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  ...newUserPrimitives<ResourceSchema>(logger, connect, {
    grants: "a team membership",
  }),

  /**
   * Leaves `login` with the policy's membership of the policy's team: `PUT`s
   * the role, or removes the membership when it's `null`.
   *
   * A grant sends the requested role, and a revoke the membership from before
   * the grant. The connector doesn't tell them apart, and doesn't compare the
   * membership with the one there now: it sets it. A membership goes to an
   * active org member only ({@link setMembership}). A removal works for
   * anyone ({@link removeMembership}).
   *
   * The team is the one with the policy's id, whatever its slug is now, and
   * `login` is the user id `getUser` returned. A team that's gone refuses a
   * membership, and a `null` succeeds: no membership of it can be left.
   */
  setPoliciesForUser: async (context, login, _user, policies) => {
    const { requestId, org } = context;
    const { teamId, role } = onlyPolicy(policies, {
      requestId,
      access: "a GitHub team membership",
    });
    const log = logger.child({ requestId, org, teamId, login, role });
    const github = await connect(context);
    const changeTarget: GitHubTarget = { org, login, changingAccess: true };
    // The slug, for messages. Ids aren't reused, so a team without one was
    // deleted.
    const team = await callGitHub(
      () => github.fetchCurrentTeamSlug(teamId),
      changeTarget
    );
    const target = team === null ? changeTarget : { ...changeTarget, team };
    if (role === null) {
      await callGitHub(
        () => removeMembership(github, log, { org, team, teamId, login }),
        target
      );
      return;
    }
    if (team === null) {
      log.warn("refused a membership of a team that doesn't exist any more");
      throw toConnectorError(new TeamNotFoundError(teamId), changeTarget);
    }
    await callGitHub(
      () => setMembership(github, log, { org, team, teamId, login }, role),
      target
    );
  },

  list: async (query) => {
    const { org } = query.context;
    const github = await connect(query.context);
    switch (query.type) {
      case "team": {
        const teams = await callGitHub(() => github.listTeams(), { org });
        // Keyed by the slug, the form a requestor names a team in.
        return teams.map(({ slug, name }) => ({ key: slug, value: name }));
      }
      case "team-id": {
        const team = await callGitHub(() => github.fetchTeam(query.team), {
          org,
          team: query.team,
        });
        // `[]` when the org has no team with that slug.
        return team === null ? [] : [{ key: team.teamId, value: team.slug }];
      }
      case "team-membership": {
        const { teamId, login } = query;
        const role = await callGitHub(
          () => github.fetchTeamMembership({ teamId, login }),
          { org, login }
        );
        return role === null ? [] : [{ key: role, value: role }];
      }
      case "member":
      case "account":
        return listUsers(github, query);
      default:
        throw throwAssertNever(query);
    }
  },
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newTeamPrimitives(ctx.logger, connectGitHub)
  );
