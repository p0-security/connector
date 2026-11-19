import {
  type AnyConnectorTRPCInstance,
  type ResourceRootConnectorPrimitives,
  newResourceRootRouter,
} from "@p0security/connector-core";

import { GRANT_LOGIN_PATTERN } from "../../context.ts";
import { newNotImplementedError } from "../../not-implemented.ts";
import { type RoleSchema, spec } from "./definition.ts";

/**
 * The grant login lifecycle, as resource-root primitives.
 *
 * The resource-root "user" is a grant login: a login role named
 * `p0v_<grant key>`, created for exactly one grant. P0 chooses the name; the
 * connector refuses any other. Each policy is one approved role, which the
 * connector grants and never creates or alters.
 *
 * - `getUser` finds the grant login. It returns the login only when both the
 *   role and its grant secret exist, so that `createUser` finishes a
 *   half-prepared login.
 * - `createUser` prepares the grant login: it creates the role unable to log
 *   in, with a random password, `VALID UNTIL` the deadline, and the comment.
 *   Then it creates the grant secret and writes the password to it. It may
 *   reset the password of a prepared login that was never activated, because
 *   nobody can have used it.
 * - `setPoliciesForUser` grants each approved role, then activates the
 *   login. It is idempotent, and never changes the password of an activated
 *   login. With no policies (the revoke path) it performs the database
 *   cutoff instead: it disables the login, clears its password, ends its
 *   sessions and verifies that none remain. It throws when the cutoff cannot
 *   be confirmed, so that P0 keeps retrying.
 * - `deleteUser` cleans up after the database cutoff: it deletes the grant
 *   secret and leaves the retired login in place for audit. A retired login
 *   is never reactivated.
 * - `list` returns, for a target, the roles a grant can be approved for, or
 *   its databases.
 *
 * The P0 control plane must serialize calls for the same grant login.
 *
 * Only `validation` is implemented. Every other primitive throws
 * {@link newNotImplementedError}.
 */
export const newRolePrimitives =
  (): ResourceRootConnectorPrimitives<RoleSchema> => ({
    validation: () => ({
      user: {
        userIsNamespacedByBody: async (login) =>
          GRANT_LOGIN_PATTERN.test(login),
        userIsNamespacedById: async (login) => GRANT_LOGIN_PATTERN.test(login),
      },
    }),

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

/** The role access type: the grant login is granted one approved role per
 * policy. See {@link newRolePrimitives} for the lifecycle. */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter(t, spec, newRolePrimitives);
