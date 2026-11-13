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
 * PingOne AWS IAM Federation role lifecycle
 *
 * The user is a PingOne user, found by email. The resource is a value of the
 * user's role attribute: binding adds it, and unbinding removes it. P0
 * creates no PingOne user, and a value needs no setup, so the other
 * primitives do nothing.
 *
 * The P0 control plane must serialize binds and unbinds for the same user.
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
          message: `PingOne has no user with the email ${email}.`,
          payload: {},
          type: "object_not_found",
        });
      },

      deleteUser: noop,

      createResource: async (_context, role) => role,
      addPolicyToResource: noop,
      removePolicyFromResource: noop,
      deleteResource: noop,

      bindResourceToUser: async (context, role, _userId, email) => {
        await addRole({ ...context, email, role }, log(context));
      },

      unbindResourceFromUser: async (context, role, _userId, email) => {
        await removeRole({ ...context, email, role }, log(context));
      },

      list: async () => [],
    };
  });
