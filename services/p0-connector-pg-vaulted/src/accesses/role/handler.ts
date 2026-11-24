import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  type ResourceRootConnectorPrimitives,
  newResourceRootRouter,
} from "@p0security/connector-core";

import { GRANT_LOGIN_PATTERN, isGrantSecretOfLogin } from "../../context.ts";
import {
  type ManagerDependencies,
  readManagerCredential,
  withManager,
} from "../../manager.ts";
import { newNotImplementedError } from "../../not-implemented.ts";
import { listDatabases, listGrantableRoles } from "../../postgres/catalog.ts";
import { type RoleSchema, spec } from "./definition.ts";

/** What `list` returns for each type of its query, by name. */
const LISTERS = { role: listGrantableRoles, database: listDatabases };

/**
 * The grant login lifecycle, as resource-root primitives. The resource-root
 * "user" is a grant login: a login role named `p0v_<grant key>`, created for
 * exactly one grant. P0 chooses the name; the connector refuses any other,
 * and refuses a grant secret that is another login's.
 *
 * What each primitive is to do is in the README, under Lifecycle. Only
 * `validation` and `list` are implemented. Every other primitive throws
 * {@link newNotImplementedError}.
 */
export const newRolePrimitives = (
  ctx: ConnectorContext,
  dependencies: ManagerDependencies = {}
): ResourceRootConnectorPrimitives<RoleSchema> => ({
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

  list: async ({ type, context: target }) => {
    const { host, port, database } = target;
    const logger = ctx.logger.child({ host, port, database, type });
    const credential = await readManagerCredential(target, dependencies);
    const names = await withManager(
      target,
      credential,
      dependencies,
      logger,
      ({ query }) => LISTERS[type](query)
    );
    logger.info({ count: names.length }, "listed from the PostgreSQL target");
    return names.map((name) => ({ key: name, value: name }));
  },
});

export const router = (
  t: AnyConnectorTRPCInstance,
  dependencies: ManagerDependencies = {}
) =>
  newResourceRootRouter(t, spec, (ctx) => newRolePrimitives(ctx, dependencies));
