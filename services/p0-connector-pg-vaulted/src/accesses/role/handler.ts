import {
  type AnyConnectorTRPCInstance,
  type ResourceRootConnectorPrimitives,
  newResourceRootRouter,
} from "@p0security/connector-core";

import { GRANT_LOGIN_PATTERN, isGrantSecretOfLogin } from "../../context.ts";
import { newNotImplementedError } from "../../not-implemented.ts";
import { type RoleSchema, spec } from "./definition.ts";

/**
 * The grant login lifecycle, as resource-root primitives. The resource-root
 * "user" is a grant login: a login role named `p0v_<grant key>`, created for
 * exactly one grant. P0 chooses the name; the connector refuses any other,
 * and refuses a grant secret that is another login's.
 *
 * What each primitive is to do is in the README, under Lifecycle. Only
 * `validation` is implemented. Every other primitive throws
 * {@link newNotImplementedError}.
 */
export const newRolePrimitives =
  (): ResourceRootConnectorPrimitives<RoleSchema> => ({
    validation: ({ secretName }) => {
      const isGrantLoginOfSecret = async (login: string) =>
        GRANT_LOGIN_PATTERN.test(login) &&
        isGrantSecretOfLogin(secretName, login);

      return {
        user: {
          userIsNamespacedByBody: isGrantLoginOfSecret,
          userIsNamespacedById: isGrantLoginOfSecret,
        },
      };
    },

    getUser: async () => {
      throw newNotImplementedError("getUser");
    },

    createUser: async () => {
      throw newNotImplementedError("createUser");
    },

    deleteUser: async () => {
      throw newNotImplementedError("deleteUser");
    },

    setPoliciesForUser: async () => {
      throw newNotImplementedError("setPoliciesForUser");
    },

    list: async () => {
      throw newNotImplementedError("list");
    },
  });

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter(t, spec, newRolePrimitives);
