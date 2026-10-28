import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
} from "@p0security/connector";

import { newAuth0Client } from "../../auth0/client.ts";
import { toConnectorError } from "../../auth0/errors.ts";
import type { PermissionRef } from "../../auth0/management.ts";
import { list } from "../common/list.ts";
import { emailUserPrimitives, onePolicy } from "../common/primitives.ts";
import { requireRequestor } from "../common/user.ts";
import { adding, removing } from "../common/writes.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

/**
 * The Auth0 `permission` access: a permission on an API, assigned to the
 * requestor's Auth0 user directly, just in time, and removed at expiry.
 *
 * Only the direct assignment is ever touched. A permission the user also
 * holds through a role stays with the role when the grant ends, and P0
 * decides "already held" from direct assignments alone.
 *
 * A grant is gated by the allowed domains, and by the Auth0 user still having
 * the requestor's email. A revoke isn't.
 */
export const newPermissionPrimitives = (
  logger: Logger
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  ...emailUserPrimitives,

  /** Assigns the policy's permission, or with a `null` policy removes the request's. */
  setPoliciesForUser: async (context, email, _user, policies) => {
    const { requestId, tenant, auth0UserId: userId } = context;
    const policy = onePolicy(policies, { requestId, access: "permission" });
    const permission: PermissionRef = {
      resourceServerIdentifier:
        policy?.resourceServerIdentifier ?? context.resourceServerIdentifier,
      permissionName: policy?.permissionName ?? context.permissionName,
    };
    const log = logger.child({ requestId, tenant, userId, ...permission });
    const auth0 = newAuth0Client({ ...context, log });
    const isHeldDirectly = async () =>
      (
        await auth0.listUserPermissions(
          userId,
          permission.resourceServerIdentifier
        )
      ).some(
        (held) =>
          held.direct && held.permissionName === permission.permissionName
      );
    try {
      if (policy !== null) {
        await requireRequestor(auth0, log, { tenant, email, userId });
        await adding(
          log,
          "permission",
          () => auth0.assignUserPermission(userId, permission),
          isHeldDirectly
        );
      } else {
        // A 404 means the user or the API is gone, and the assignment with it.
        await removing(log, "permission", () =>
          auth0.removeUserPermission(userId, permission)
        );
      }
    } catch (error) {
      throw toConnectorError(error, {
        tenant,
        subject: `permission ${permission.permissionName} on ${permission.resourceServerIdentifier}`,
      });
    }
  },

  list: (query) => list(logger, query),
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newPermissionPrimitives(ctx.logger)
  );
