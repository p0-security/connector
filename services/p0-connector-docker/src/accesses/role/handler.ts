import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector-core";

import { requireAllowedDomains } from "../../allowed-domains.ts";
import type { DockerHubError, OrgMember } from "../../dockerhub/api.ts";
import {
  type DockerHubClient,
  newDockerHubClient,
} from "../../dockerhub/client.ts";
import {
  callDockerHub,
  isInvalidRequest,
  isNotFound,
  reasonOf,
  toConnectorError,
} from "../../dockerhub/errors.ts";
import {
  type CoreRole,
  type StandingMember,
  coreRole,
  spec,
} from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

/** Who a call is for: the requestor's P0 email, in one org. */
type Target = { org: string; email: string };

// Each refusal is a `validation_error`, the type whose message P0 shows the
// requestor, and is only ever thrown before the connector has written
// anything.

const refusal = ({
  reason,
  target: { org, email },
  message,
  extra = {},
}: {
  reason: string;
  target: Target;
  message: string;
  extra?: Record<string, string>;
}) =>
  new ConnectorError({
    type: "validation_error",
    message,
    payload: { reason, org, email, ...extra },
  });

const domainNotAllowed = (target: Target) =>
  refusal({
    reason: "domain_not_allowed",
    target,
    message: `Your email domain isn't allowed for Docker Hub organization ${target.org}. Ask your P0 admin to check the connector's allowed domains.`,
  });

const accountChanged = (target: Target, { username, uuid }: StandingMember) =>
  refusal({
    reason: "account_changed",
    target,
    message:
      "Your Docker account changed after you requested access. Request access again.",
    extra: { username, uuid },
  });

const joinedSinceRequest = (target: Target) =>
  refusal({
    reason: "joined_since_request",
    target,
    message: `You joined ${target.org} after you requested access. Request access again.`,
  });

const pendingInvite = (target: Target) =>
  refusal({
    reason: "pending_invite",
    target,
    message: `You have a pending invite to ${target.org}. Accept it, or ask an owner of ${target.org} to cancel it. Then request again.`,
  });

const memberUnderAnotherEmail = (target: Target) =>
  refusal({
    reason: "member_under_another_email",
    target,
    message: `Docker Hub says you're already in ${target.org}, but no member has the email ${target.email}. Your Docker account probably uses a different email. Ask your Docker Hub admin to check it.`,
  });

const inviteRefused = (target: Target, dockerReason: string) =>
  refusal({
    reason: "invite_refused",
    target,
    // Docker's own text may already end in a full stop.
    message: `Docker Hub refused the invite to ${target.org}: ${dockerReason.replace(/\.$/, "")}.`,
    extra: { dockerReason },
  });

const moreThanOneMember = (target: Target) =>
  refusal({
    reason: "more_than_one_member",
    target,
    message: `More than one member of ${target.org} has the email ${target.email}. Ask your Docker Hub admin to fix this.`,
  });

// Not a `validation_error`, which says nothing was written: by now the
// connector has cancelled an invite. P0 shows a `dependency_violation`'s
// message too, so Docker Hub's reason still gets through.
const cancelRefused = (
  { org, email }: Target,
  error: DockerHubError,
  cancelled: number
) =>
  new ConnectorError({
    type: "dependency_violation",
    message: `Docker Hub refused to cancel one of the pending invites to ${org}: ${reasonOf(error)}`,
    payload: { org, email, cancelled },
  });

// The same, when Docker Hub refuses to remove the member instead.
const removeRefused = (
  { org, email }: Target,
  username: string,
  error: DockerHubError,
  cancelled: number
) =>
  new ConnectorError({
    type: "dependency_violation",
    // Docker's own text may already end in a full stop.
    message: `Docker Hub refused to remove ${username} from ${org}: ${reasonOf(error).replace(/\.$/, "")}. P0 cancelled ${
      cancelled === 1 ? "the pending invite" : `${cancelled} pending invites`
    } to ${email}, but ${username} is still a member of ${org}.`,
    payload: { org, email, username, cancelled },
  });

const RANK: Record<CoreRole, number> = { member: 0, editor: 1, owner: 2 };

/** Whether going from the role `from` to `to` lowers it. A custom role has no rank, so leaving one never counts. */
const lowersRole = ({ from, to }: { from: string; to: CoreRole }): boolean => {
  const core = coreRole.safeParse(from);
  return core.success && RANK[to] < RANK[core.data];
};

const isSameEmail = (dockerEmail: string | undefined, email: string) =>
  dockerEmail?.toLowerCase() === email.toLowerCase();

/**
 * What a grant checks before it raises the live account: the requestor's
 * email is in the allowed domains, and it's the account's Docker email.
 */
const passesGrantChecks = (live: OrgMember, { email }: Target): boolean =>
  requireAllowedDomains().allows(email) && isSameEmail(live.email, email);

/** The org member with the email, or `null`. The email is the only identity, so two members with it are refused. */
const findOneMember = async (
  docker: DockerHubClient,
  target: Target
): Promise<OrgMember | null> => {
  const [member, ...others] = await docker.findMembersByEmail(target.email);
  if (others.length > 0) throw moreThanOneMember(target);
  return member ?? null;
};

/** The live account behind a standing member's username, when it's still the account P0 recorded. */
const findStandingMember = async (
  docker: DockerHubClient,
  { username, uuid }: StandingMember
): Promise<OrgMember | null> => {
  const live = await docker.findMemberByUsername(username);
  return live?.uuid === uuid ? live : null;
};

/**
 * Sets a standing member's role, if the username still names the account P0
 * recorded and that account's Docker email is the requestor's.
 *
 * The email tie is what makes the allowed domains mean something here: P0
 * sends both an email and a username, and without it an allowed email could
 * be paired with anyone's username.
 */
const grantToStandingMember = async (
  docker: DockerHubClient,
  log: Logger,
  target: Target,
  { standingMember, role }: { standingMember: StandingMember; role: CoreRole }
) => {
  const live = await findStandingMember(docker, standingMember);
  if (!live || !passesGrantChecks(live, target)) {
    log.warn(
      { uuid: standingMember.uuid, liveUuid: live?.uuid },
      "refused a grant: the standing member's account isn't the one P0 recorded"
    );
    throw accountChanged(target, standingMember);
  }
  await docker.setRole({ username: standingMember.username, role });
  log.info("set the standing member's role");
};

/** Invites someone who isn't in the org. This path only ever invites: it never sets a role. */
const inviteRequestor = async (
  docker: DockerHubClient,
  log: Logger,
  target: Target,
  role: CoreRole
) => {
  if (await findOneMember(docker, target)) throw joinedSinceRequest(target);

  const invites = await docker.findInvites(target.email);
  if (invites.some((invite) => invite.role !== role)) {
    throw pendingInvite(target);
  }
  if (invites.length > 0) {
    // Usually P0's own: the framework runs a checked step twice.
    log.info("a pending invite already gives this role");
    return;
  }

  const result = await docker
    .invite({ email: target.email, role })
    .catch((error: unknown) => {
      throw isInvalidRequest(error)
        ? inviteRefused(target, reasonOf(error))
        : error;
    });
  switch (result.status) {
    case "invited":
      log.info("invited the requestor");
      return;
    case "existing_org_member":
      throw memberUnderAnotherEmail(target);
    case "refused":
      throw inviteRefused(target, result.reason);
    default:
      throw throwAssertNever(result);
  }
};

/**
 * Puts a standing member's prior role back, whatever their role is now.
 *
 * Lowering a role is never blocked. A restore that would raise it (an admin
 * lowered it during the grant) has to pass the same checks as a grant, and
 * when it doesn't, the member keeps the lower role and the revoke succeeds.
 */
const restorePriorRole = async (
  docker: DockerHubClient,
  log: Logger,
  target: Target,
  standingMember: StandingMember
) => {
  const { username, priorRole } = standingMember;
  const live = await findStandingMember(docker, standingMember);
  if (!live) {
    log.info("the standing member is no longer in the org");
    return;
  }
  if (live.role === priorRole) return;

  if (
    !lowersRole({ from: live.role, to: priorRole }) &&
    !passesGrantChecks(live, target)
  ) {
    log.warn(
      { priorRole, liveRole: live.role },
      "left the lower role in place: restoring the prior role would raise it, and the grant's checks don't pass"
    );
    return;
  }
  try {
    await docker.setRole({ username, role: priorRole });
  } catch (error) {
    // They left between the lookup and the PUT.
    if (!isNotFound(error)) throw error;
    return;
  }
  log.info({ priorRole }, "restored the prior role");
};

/**
 * Puts the org back as it was before P0 invited someone: cancels every pending
 * invite to their email, then removes the member with it, in the same run, so
 * a second run finds nothing left to take back.
 *
 * It removes a member only when P0's grant completed. Otherwise whoever holds
 * the email joined some other way.
 */
const revokeInvited = async (
  docker: DockerHubClient,
  log: Logger,
  target: Target,
  grantCompleted: boolean
) => {
  const invites = await docker.findInvites(target.email);
  // Refuses two members with the email before any invite is cancelled. The
  // member to remove is looked up again afterwards, because an invite can be
  // accepted while it's being cancelled.
  if (grantCompleted && invites.length > 0) await findOneMember(docker, target);

  let cancelled = 0;
  for (const { id } of invites) {
    try {
      await docker.cancelInvite(id);
      cancelled += 1;
    } catch (error) {
      // Gone already: cancelled by someone else, or accepted.
      if (isNotFound(error)) continue;
      throw cancelled > 0 && isInvalidRequest(error)
        ? cancelRefused(target, error, cancelled)
        : error;
    }
  }
  if (cancelled > 0) log.info({ cancelled }, "cancelled the pending invites");
  if (!grantCompleted) {
    log.info("the grant never completed, so no member is removed");
    return;
  }

  const member = await findOneMember(docker, target);
  if (!member) return;
  try {
    await docker.removeMember(member.username);
  } catch (error) {
    // They left between the lookup and the DELETE.
    if (isNotFound(error)) return;
    throw cancelled > 0 && isInvalidRequest(error)
      ? removeRefused(target, member.username, error, cancelled)
      : error;
  }
  log.info(
    { username: member.username, uuid: member.uuid },
    "removed the invited member from the org"
  );
};

/**
 * The Docker Hub `role` access: an org role, granted just in time and taken
 * back at expiry.
 *
 * The user is the requestor's P0 email. A standing member has their role set
 * and gets their prior role back. Anyone else is invited, and loses the
 * invite and, once P0's grant completed, the membership.
 *
 * The allowed domains gate a grant, both lookups and a restore that would
 * raise a role. Nothing else a revoke does is gated, so tightening the
 * pattern can't strand access granted earlier.
 */
export const newRolePrimitives = (
  logger: Logger
): ResourceRootConnectorPrimitives<ResourceSchema> => {
  const requireAllowedEmail = (target: Target) => {
    if (requireAllowedDomains().allows(target.email)) return;
    logger.info(target, "refused an email outside the allowed domains");
    throw domainNotAllowed(target);
  };

  return {
    // The perimeter's own check can't tell a grant from a revoke, and `list`
    // never runs it.
    validation: () => ({ user: null }),

    // Never `null`, and nothing is looked up: P0 calls this on a revoke too,
    // and can't say which it is.
    getUser: async (_context, email) => email,

    // Never reached, since `getUser` never returns `null`.
    createUser: async (_context, email) => email,

    // A deliberate no-op. `setPoliciesForUser` with a `null` role already
    // took everything back, and a standing member was in the org before P0
    // got involved.
    deleteUser: async () => {},

    /** Leaves the requestor with the policy's role: a core role to grant, or `null` to take back what P0 gave. */
    setPoliciesForUser: async (context, email, _user, policies) => {
      const { requestId, org, tokenSecret, standingMember, grantCompleted } =
        context;
      const [policy, ...others] = policies;
      if (policy === undefined || others.length > 0) {
        // `unknown`: P0 always sends exactly one policy, so this is a P0 bug
        // the requestor can't correct.
        throw new ConnectorError({
          type: "unknown",
          message: `Expected exactly 1 policy for a Docker Hub role, got ${policies.length}`,
          payload: { requestId, nPolicies: policies.length },
        });
      }

      const { role } = policy;
      const target: Target = { org, email };
      if (role !== null) requireAllowedEmail(target);

      const log = logger.child({
        requestId,
        org,
        email,
        role,
        username: standingMember?.username,
      });
      const docker = newDockerHubClient({ org, tokenSecret, log });
      try {
        if (role !== null && standingMember) {
          await grantToStandingMember(docker, log, target, {
            standingMember,
            role,
          });
        } else if (role !== null) {
          await inviteRequestor(docker, log, target, role);
        } else if (standingMember) {
          await restorePriorRole(docker, log, target, standingMember);
        } else {
          await revokeInvited(docker, log, target, grantCompleted);
        }
      } catch (error) {
        throw toConnectorError(error, {
          org,
          username: standingMember?.username,
        });
      }
    },

    list: async (query) => {
      const { context, email } = query;
      const target: Target = { org: context.org, email };
      requireAllowedEmail(target);
      const log = logger.child({ ...target, type: query.type });
      const docker = newDockerHubClient({ ...context, log });
      switch (query.type) {
        case "member": {
          const member = await callDockerHub(
            () => findOneMember(docker, target),
            target
          );
          // `[]` when no member has the email: P0 then invites them.
          return member
            ? [{ key: member.username, value: member.uuid, group: member.role }]
            : [];
        }
        case "invite": {
          const invites = await callDockerHub(
            () => docker.findInvites(email),
            target
          );
          return invites.map(({ id, role }) => ({ key: id, value: role }));
        }
        default:
          throw throwAssertNever(query);
      }
    },
  };
};

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newRolePrimitives(ctx.logger)
  );
