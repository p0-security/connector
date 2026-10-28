import type { Logger } from "@p0security/connector";
import { isEqual } from "lodash-es";

import {
  type CloudClient,
  type PolicyRequest,
  type Role,
  newCloudClient,
} from "../../cloud/client.ts";
import { callCloud, isRoleWriteRefused } from "../../cloud/errors.ts";
import {
  basePolicies,
  findRole,
  holdsPolicies,
  requireRole,
  rolesNamed,
  userActor,
} from "../../cloud/roles.ts";
import { isP0Name, requireP0Role } from "../../namespace.ts";
import { refusal } from "../../refusals.ts";
import type { ListerQuery, RequestContext } from "./definition.ts";
import { list } from "./list.ts";
import { findMember, requireAllowedEmail } from "./member.ts";

/**
 * The primitives every ClickHouse access shares. Each request gets one
 * custom role, named by P0 (`p0_…`), which is both the resource body and
 * the resource ID: every primitive finds the role by that name in
 * `GET …/roles`. The user is the requestor's email, and nothing is created
 * for it: the role's only actor is the organization member with that email.
 *
 * A grant creates the role with the base policies and no actors, sets its
 * policies to the base policies plus the access's, and binds the member. The
 * policies must be written before the bind: on INT-669's live check, a
 * policy change to a role that already had an actor never took effect
 * (still not after 643 seconds). A revoke unbinds the member, sets the policies back to the base policies
 * (not needed once the role has no actors), and deletes the role, through
 * every role with the name. No revoke step fails because the role is gone.
 */

/** One primitive's call on the request's role. */
type RoleCall = {
  cloud: CloudClient;
  log: Logger;
  organizationId: string;
  serviceId: string;
  name: string;
};

/**
 * Refuses a role that isn't P0's before anything else, then runs `fn` with a
 * client and a log for the role, mapping any ClickHouse Cloud failure.
 */
const withRole = async <T>(
  logger: Logger,
  context: RequestContext,
  name: string,
  fn: (call: RoleCall) => Promise<T>
): Promise<T> => {
  requireP0Role(name);
  const { requestId, organization, serviceId } = context;
  const { organizationId } = organization;
  const log = logger.child({
    requestId,
    organizationId,
    serviceId,
    role: name,
  });
  const cloud = newCloudClient({ ...organization, log });
  return callCloud(() => fn({ cloud, log, organizationId, serviceId, name }), {
    organizationId,
    subject: `role ${name}`,
  });
};

/**
 * Changes every role with the name on a revoke, one at a time. Two can
 * share a name, after a create retried on a timeout or a name collision,
 * and a revoke must take access back through each. A role that's gone has
 * nothing left to take back, so none in the listing is done. ClickHouse
 * Cloud may answer a write to a role that went in the meantime with a 400
 * or a 404, so after either the roles are listed again, and that role gone
 * is done too.
 */
const reviseOnRevoke = async (
  { cloud, log, name }: RoleCall,
  revise: (role: Role) => Promise<void>
): Promise<void> => {
  const roles = rolesNamed(await cloud.listRoles({ target: name }), name);
  if (roles.length === 0) {
    log.info("the role is already gone");
    return;
  }
  if (roles.length > 1) {
    log.warn(
      { roles: roles.length },
      "more than one role has the request's name; revoking through each"
    );
  }
  for (const role of roles) {
    try {
      await revise(role);
    } catch (error) {
      if (!isRoleWriteRefused(error)) throw error;
      const listed = await cloud.listRoles({ target: name });
      if (listed.some(({ id }) => id === role.id)) throw error;
      log.info(
        { roleId: role.id },
        "the role went while the connector changed it"
      );
    }
  }
};

const isP0Role = async (name: string) => isP0Name(name);

export const newCommonClickHousePrimitives = (logger: Logger) => ({
  // Users aren't namespaced: the user is the requestor's email. The role is
  // P0's when its name starts with `p0_`.
  validation: () => ({
    user: null,
    resource: {
      resourceIsNamespacedById: isP0Role,
      resourceIsNamespacedByBody: isP0Role,
    },
  }),

  // Never `null`, and nothing is looked up: P0 calls this on a revoke too,
  // which must still work after the person has left the organization.
  getUser: async (_context: RequestContext, email: string) => email,

  // Never reached, since `getUser` never returns `null`. P0 never creates a
  // ClickHouse Cloud user.
  createUser: async (
    context: RequestContext,
    email: string
  ): Promise<never> => {
    throw refusal({
      reason: "not_member",
      message: `P0 doesn't create ClickHouse Cloud users. ${email} must join the ClickHouse Cloud organization ${context.organization.organizationId} first, then request access again.`,
      payload: { email },
    });
  },

  // A deliberate no-op: P0 created no user, so there's none to delete.
  deleteUser: async () => {},

  /**
   * Creates the role with the base policies and no actors, unless an earlier
   * attempt already did. ClickHouse Cloud roles have no description, so the
   * request's is logged with the request ID instead.
   */
  createResource: async (context: RequestContext, name: string) =>
    withRole(logger, context, name, async (call) => {
      const { cloud, log, organizationId, serviceId } = call;
      const { requestId, description } = context;
      if (
        findRole(await cloud.listRoles({ target: name }), {
          name,
          organizationId,
        })
      ) {
        log.info({ requestId, description }, "the role is already there");
        return name;
      }
      await cloud.createRole({
        name,
        actors: [],
        policies: basePolicies({ organizationId, serviceId }),
      });
      log.info({ requestId, description }, "created the role");
      return name;
    }),

  /** Deletes the role. One that's already gone is done. */
  deleteResource: async (context: RequestContext, name: string) =>
    withRole(logger, context, name, (call) =>
      reviseOnRevoke(call, async (role) => {
        await call.cloud.deleteRole(role);
        call.log.info(
          "deleted the role; ClickHouse Cloud may take up to 10 minutes to remove the access it gave"
        );
      })
    ),

  /**
   * Makes the member with the requestor's email the role's only actor. The
   * email's domain must be one `DOMAIN_ALLOW_PATTERN` allows, and exactly
   * one member must have it. The member's own roles are never read or
   * written.
   */
  bindResourceToUser: async (
    context: RequestContext,
    name: string,
    email: string
  ) =>
    withRole(logger, context, name, async (call) => {
      const { cloud, log, organizationId } = call;
      requireAllowedEmail(email, log);
      const member = await findMember(cloud, { organizationId, email });
      if (member === undefined) {
        throw refusal({
          reason: "not_member",
          message: `${email} isn't a member of the ClickHouse Cloud organization ${organizationId}. Join the organization, then request access again.`,
          payload: { email },
        });
      }
      const role = requireRole(await cloud.listRoles({ target: name }), {
        name,
        organizationId,
      });
      const actors = [userActor(member.userId)];
      if (!isEqual(role.actors, actors)) {
        await cloud.updateRole(role, { actors });
      }
      log.info(
        { email, userId: member.userId },
        "bound the role to the member"
      );
    }),

  /**
   * Leaves the role with no actors. Never checked against the allowed
   * domains, so narrowing them can't strand access granted before. A role
   * that's gone is done.
   */
  unbindResourceFromUser: async (
    context: RequestContext,
    name: string,
    email: string
  ) =>
    withRole(logger, context, name, (call) =>
      reviseOnRevoke(call, async (role) => {
        if (role.actors.length > 0) {
          await call.cloud.updateRole(role, { actors: [] });
        }
        call.log.info({ email }, "unbound the role from its member");
      })
    ),

  list: (query: ListerQuery) => list(logger, query),
});

/**
 * What an access's policy becomes on the role: the policies it adds to the
 * base ones. `roles` is the organization's roles as the grant found them.
 */
export type ToPolicies<Policy> = (
  policy: Policy,
  scope: { organizationId: string; serviceId: string; roles: readonly Role[] }
) => PolicyRequest[];

/**
 * The two policy primitives, for an access that says what its policy
 * becomes.
 *
 * P0 sends one policy per request, so adding one sets the role's policies to
 * the base policies plus that one's, and removing one sets them back to the
 * base policies. Both are idempotent, so a step can run again.
 *
 * `systemRolesOf` names the system roles an access's policy copies, which
 * the roles listing must be able to read: any other role it can't read,
 * but P0's, is skipped.
 */
export const newPolicyPrimitives = <Policy extends { type: string }>(
  logger: Logger,
  toPolicies: ToPolicies<Policy>,
  systemRolesOf: (policy: Policy) => readonly string[] = () => []
) => ({
  addPolicyToResource: async (
    context: RequestContext,
    name: string,
    policy: Policy
  ) =>
    withRole(logger, context, name, async (call) => {
      const { cloud, log, organizationId, serviceId } = call;
      const roles = await cloud.listRoles({
        target: name,
        systemRoles: systemRolesOf(policy),
      });
      const role = requireRole(roles, { name, organizationId });
      const policies = [
        ...basePolicies({ organizationId, serviceId }),
        ...toPolicies(policy, { organizationId, serviceId, roles }),
      ];
      if (!holdsPolicies(role, policies)) {
        await cloud.updateRole(role, { policies });
      }
      log.info({ access: policy.type, policies }, "gave the role the access");
    }),

  removePolicyFromResource: async (
    context: RequestContext,
    name: string,
    policy: Policy
  ) =>
    withRole(logger, context, name, (call) =>
      reviseOnRevoke(call, async (role) => {
        // With no actors the role gives no one anything, and the delete
        // comes next, so its policies aren't written: that PATCH names the
        // service, and could fail when the service is gone.
        if (role.actors.length === 0) {
          call.log.info(
            { access: policy.type },
            "the role has no actors, so its access is left for the delete"
          );
          return;
        }
        const policies = basePolicies(call);
        if (!holdsPolicies(role, policies)) {
          await call.cloud.updateRole(role, { policies });
        }
        call.log.info({ access: policy.type }, "took the access off the role");
      })
    ),
});
