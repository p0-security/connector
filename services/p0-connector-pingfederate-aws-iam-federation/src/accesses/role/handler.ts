import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type ResourceHierarchySchemaOf,
  newResourceHierarchyRouter,
} from "@p0security/connector-core";

import { addRole, findUserId, removeRole } from "./assignment.ts";
import { spec } from "./definition.ts";

type Schema = ResourceHierarchySchemaOf<typeof spec>;

const noop = async () => {};

/**
 * PingFederate AWS IAM Federation role lifecycle
 *
 * The user is a SCIM user in PingFederate, found by work email. The resource
 * is a value of the user's role attribute: binding adds it, and unbinding
 * removes it. P0 creates no user, and a value needs no setup, so the other
 * primitives do nothing.
 *
 * PingFederate can lose one of two changes for the same user at the same
 * time, so P0 must not send them together.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceHierarchyRouter<Schema>(t, spec, (ctx: ConnectorContext) => {
    const log = (context: Schema["RequestContext"]) =>
      ctx.logger.child({ requestId: context.requestId });

    return {
      validation: () => ({ resource: null, user: null }),

      getUser: (context, email) => findUserId(context, email, log(context)),

      createUser: async (_context, email) => {
        throw new ConnectorError({
          message: `PingFederate has no user with the work email ${email}.`,
          payload: {},
          type: "object_not_found",
        });
      },

      deleteUser: noop,

      createResource: async (_context, role) => role,
      addPolicyToResource: noop,
      removePolicyFromResource: noop,
      deleteResource: noop,

      bindResourceToUser: async (context, role, userId) => {
        await addRole({ ...context, userId, role }, log(context));
      },

      unbindResourceFromUser: async (context, role, userId) => {
        await removeRole({ ...context, userId, role }, log(context));
      },

      list: async () => [],
    };
  });
