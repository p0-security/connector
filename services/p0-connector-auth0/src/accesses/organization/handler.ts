import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
} from "@p0security/connector-core";

import { Auth0Error } from "../../auth0/api.ts";
import { type Auth0Client, newAuth0Client } from "../../auth0/client.ts";
import {
  isInvalidRequest,
  reasonOf,
  toConnectorError,
} from "../../auth0/errors.ts";
import { list } from "../common/list.ts";
import { emailUserPrimitives, onePolicy } from "../common/primitives.ts";
import { requireRequestor } from "../common/user.ts";
import { adding, removing } from "../common/writes.ts";
import { type OrganizationRequestContext, spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

type Grant = { organizationId: string; roleId: string | undefined };

const isMember = async (
  auth0: Auth0Client,
  organizationId: string,
  userId: string
) =>
  (await auth0.listUserOrganizations(userId)).some(
    ({ id }) => id === organizationId
  );

const addRole = (
  auth0: Auth0Client,
  log: Logger,
  {
    organizationId,
    userId,
    roleId,
  }: { organizationId: string; userId: string; roleId: string }
) =>
  adding(
    log,
    "role",
    () => auth0.assignMemberRole(organizationId, userId, roleId),
    async () =>
      (await auth0.listMemberRoles(organizationId, userId)).some(
        ({ id }) => id === roleId
      )
  );

/** Why Auth0 refused a step, for a message. */
const reasonFor = (error: unknown) =>
  error instanceof Auth0Error ? reasonOf(error) : "it failed";

/**
 * Adds the membership P0 grants, then the role in it.
 *
 * When the role fails after this call added the membership, it takes the
 * membership back, so a failed grant leaves the organization as it was, and
 * fails as a `dependency_violation`: by then the connector has written. A
 * membership it found already there, such as one an admin added since stage,
 * is left alone.
 */
const grantToNonMember = async (
  auth0: Auth0Client,
  log: Logger,
  userId: string,
  { organizationId, roleId }: Grant
) => {
  const added = await adding(
    log,
    "membership",
    () => auth0.addMember(organizationId, userId),
    () => isMember(auth0, organizationId, userId)
  );
  if (roleId === undefined) return;
  try {
    await addRole(auth0, log, { organizationId, userId, roleId });
  } catch (error) {
    if (!added) throw error;
    log.warn("removing the membership after the role failed");
    const removed = await removing(log, "membership", () =>
      auth0.removeMember(organizationId, userId)
    ).then(
      () => true,
      () => false
    );
    throw new ConnectorError({
      type: "dependency_violation",
      message: removed
        ? `Auth0 refused to assign the role in organization ${organizationId}: ${reasonFor(error)}. P0 removed the membership it had added.`
        : `Auth0 refused to assign the role in organization ${organizationId}: ${reasonFor(error)}. P0 added the membership but couldn't remove it again. Remove ${userId} from ${organizationId} by hand.`,
      payload: { organizationId, roleId, userId, membershipRemoved: removed },
    });
  }
};

/**
 * Takes back what P0 added, in one pass: the role, then the membership. The
 * role goes first because whether removing a member also drops their roles
 * in the organization isn't documented.
 *
 * A membership is removed only when the user wasn't a member at stage, and a
 * role only when the member didn't already hold it then. So a rerun, or the
 * rollback of a grant that failed partway, never removes a member or a role
 * that was there before P0.
 *
 * When Auth0 refuses the membership after this call removed the role, it
 * fails as a `dependency_violation`, as a grant does: by then the connector
 * has written. Any other failure keeps its own type, so P0 still retries a
 * rate limit or an outage.
 */
const revoke = async (
  auth0: Auth0Client,
  log: Logger,
  context: OrganizationRequestContext
) => {
  const {
    auth0UserId: userId,
    organizationId,
    roleId,
    wasMember,
    priorRoleIds,
  } = context;
  const roleRemoved =
    roleId !== undefined && !priorRoleIds.includes(roleId)
      ? await removing(log, "role", () =>
          auth0.removeMemberRole(organizationId, userId, roleId)
        )
      : false;
  if (wasMember) return;
  try {
    await removing(log, "membership", () =>
      auth0.removeMember(organizationId, userId)
    );
  } catch (error) {
    if (!roleRemoved || !isInvalidRequest(error)) throw error;
    log.warn(
      "Auth0 refused the membership's removal after the role was removed"
    );
    throw new ConnectorError({
      type: "dependency_violation",
      message: `Auth0 refused to remove ${userId} from organization ${organizationId}: ${reasonFor(error)}. P0 removed the role it had added, but ${userId} is still a member. Fix what Auth0's reason names, or remove ${userId} from ${organizationId} in Auth0.`,
      payload: { organizationId, userId, roleRemoved },
    });
  }
};

/**
 * The Auth0 `organization` access: membership of an organization, optionally
 * with a tenant role in it, for the length of a grant.
 *
 * | Member at stage | Role requested  | Grant                   | Revoke                     |
 * | --------------- | --------------- | ----------------------- | -------------------------- |
 * | no              | no              | add the membership      | remove the membership      |
 * | no              | yes             | add membership, role    | remove role, membership    |
 * | yes             | yes, not held   | add the role            | remove only that role      |
 * | yes             | held, or none   | refused by P0           |                            |
 *
 * Roles are tenant roles assigned in the organization. A grant is gated by
 * the allowed domains and by the user still having the requestor's email. A
 * revoke isn't.
 */
export const newOrganizationPrimitives = (
  logger: Logger
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  ...emailUserPrimitives,

  /** Adds the policy's grant, or with a `null` policy takes back what the request context says P0 added. */
  setPoliciesForUser: async (context, email, _user, policies) => {
    const { requestId, tenant, auth0UserId: userId, wasMember } = context;
    const policy = onePolicy(policies, { requestId, access: "organization" });
    const organizationId = policy?.organizationId ?? context.organizationId;
    const roleId = policy === null ? context.roleId : policy.roleId;
    const log = logger.child({
      requestId,
      tenant,
      userId,
      organizationId,
      roleId,
      wasMember,
    });
    if (policy !== null && wasMember && roleId === undefined) {
      // P0 refuses this request: a member asking for nothing.
      throw new ConnectorError({
        type: "unknown",
        message: `Nothing to grant: the user was already a member of ${organizationId}, and no role was requested`,
        payload: { requestId, organizationId },
      });
    }
    const auth0 = newAuth0Client({ ...context, log });
    try {
      if (policy === null) {
        await revoke(auth0, log, context);
      } else {
        await requireRequestor(auth0, log, { tenant, email, userId });
        if (wasMember && roleId !== undefined) {
          await addRole(auth0, log, { organizationId, userId, roleId });
        } else {
          await grantToNonMember(auth0, log, userId, {
            organizationId,
            roleId,
          });
        }
      }
    } catch (error) {
      throw toConnectorError(error, {
        tenant,
        subject: `organization ${organizationId}`,
      });
    }
  },

  list: (query) => list(logger, query),
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newOrganizationPrimitives(ctx.logger)
  );
