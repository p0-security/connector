import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
} from "@p0security/connector-core";

import { newAuth0Client } from "../../auth0/client.ts";
import { toConnectorError } from "../../auth0/errors.ts";
import { list } from "../common/list.ts";
import { emailUserPrimitives, onePolicy } from "../common/primitives.ts";
import { requireRequestor } from "../common/user.ts";
import { adding, removing } from "../common/writes.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

/**
 * The Auth0 `role` access: a tenant role assigned to the requestor's Auth0
 * user directly, just in time, and removed at expiry.
 *
 * A grant is gated by the allowed domains, and by the Auth0 user still having
 * the requestor's email. A revoke isn't, so tightening the pattern can't
 * strand access granted earlier. It only ever touches the one role: never
 * another role, a permission or a membership.
 *
 * "Already holds the role" is refused by P0 before the grant, so a role this
 * finds assigned is P0's own, from a step the framework ran twice.
 */
export const newRolePrimitives = (
  logger: Logger
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  ...emailUserPrimitives,

  /** Assigns the policy's role, or with a `null` policy removes the request's role. */
  setPoliciesForUser: async (context, email, _user, policies) => {
    const { requestId, tenant, auth0UserId: userId } = context;
    const policy = onePolicy(policies, { requestId, access: "role" });
    const roleId = policy?.roleId ?? context.roleId;
    const log = logger.child({ requestId, tenant, userId, roleId });
    const auth0 = newAuth0Client({ ...context, log });
    try {
      if (policy !== null) {
        await requireRequestor(auth0, log, { tenant, email, userId });
        await adding(
          log,
          "role",
          () => auth0.assignUserRole(userId, roleId),
          async () =>
            (await auth0.listUserRoles(userId)).some(({ id }) => id === roleId)
        );
      } else {
        // A 404 means the user or the role is gone, and the assignment with it.
        await removing(log, "role", () => auth0.removeUserRole(userId, roleId));
      }
    } catch (error) {
      throw toConnectorError(error, { tenant, subject: `role ${roleId}` });
    }
  },

  list: (query) => list(logger, query),
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newRolePrimitives(ctx.logger)
  );
