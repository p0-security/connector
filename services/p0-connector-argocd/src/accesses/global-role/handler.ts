// Shaped after services/p0-connector-harbor/src/accesses/project-role/handler.ts:
// the resource-root primitives over a connect, with a user that is never
// created or deleted. The two accesses' handlers repeat each other on
// purpose, so project-role can be taken out without touching global-role.
import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector";

import { type ConnectArgoCd, connectArgoCd } from "../../argocd/client.ts";
import { readHeld, readRoles } from "../lines.ts";
import { spec } from "./definition.ts";
import { setPolicies } from "./policies.ts";

/** The access's types, as its schemas infer them. */
export type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

type ListerQuery = ResourceSchema["ListerQuery"];
type ListerResponse = ResourceSchema["ListerResponse"];

/** `[]`, or the one role, as a lister row. */
const rowsOf = (roles: readonly string[]): ListerResponse =>
  roles.map((role) => ({ key: role, value: role }));

/**
 * The instance's global roles, by name: Argo CD's built-ins and every role
 * the customer's policy keys name, less the connector's own and the default
 * role. With `role`, that one role, or `[]`.
 */
const listRoles = async (
  { context, role }: Extract<ListerQuery, { type: "role" }>,
  logger: Logger,
  connect: ConnectArgoCd
): Promise<ListerResponse> => {
  const { global } = await readRoles(connect, logger, context, {
    projects: false,
  });
  return rowsOf(
    role === undefined ? global : global.filter((name) => name === role)
  );
};

/**
 * Whether the user with `email` holds `role` already: `[]`, or the role.
 * The domain allowlist runs first, before the secret is read or Argo CD is
 * called, so the connector says nothing of anyone outside the domains it
 * allows.
 */
const listHeld = async (
  { context, email, role }: Extract<ListerQuery, { type: "held" }>,
  logger: Logger,
  connect: ConnectArgoCd
): Promise<ListerResponse> => {
  const held = await readHeld(connect, logger, context, email, {
    kind: "global",
    role,
  });
  return rowsOf(held ? [role] : []);
};

/**
 * The Argo CD `globalRole` access: a role on the whole instance, granted
 * just in time and taken back at expiry, as one `g, <email>, role:<name>`
 * line in `policy.p0.csv`.
 *
 * Exported separately from {@link router} so the primitives can be driven
 * against an Argo CD double.
 */
export const newGlobalRolePrimitives = (
  logger: Logger,
  connect: ConnectArgoCd
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  // The user is their SSO email, which can't carry a P0 marker, so there's
  // nothing to validate a user's namespace against.
  validation: () => ({ user: null }),

  /**
   * The user body's email, without calling Argo CD: an SSO user exists in
   * Argo CD only as the email its IdP sends. Never `null`: the framework's
   * `provisionUser` would then call `createUser`, which refuses. It also
   * runs at revoke, where nothing may stand between P0 and taking access
   * away.
   */
  getUser: async (_context, { email }) => email,

  /**
   * Refuses. `getUser` always answers, so P0 never gets here, and the
   * connector never creates Argo CD users.
   */
  createUser: async ({ requestId }) => {
    throw new ConnectorError({
      type: "unknown",
      message:
        "P0 asked the Argo CD connector to create an Argo CD user, which it never does.",
      payload: { requestId },
    });
  },

  /**
   * A no-op: there is no user to delete. P0's revoke calls it after
   * `setPoliciesForUser` has removed the line, which is all a revoke does.
   */
  deleteUser: async ({ requestId }) => {
    logger.debug(
      { requestId },
      "deleteUser is a no-op; the revoke removed the line"
    );
  },

  /** Adds P0's line for the role, or with a `null` role removes it. */
  setPoliciesForUser: (context, userId, _user, policies) =>
    setPolicies({ connect, logger, context, userId, policies }),

  list: async (query) => {
    switch (query.type) {
      case "role":
        return await listRoles(query, logger, connect);
      case "held":
        return await listHeld(query, logger, connect);
      default:
        throw throwAssertNever(query);
    }
  },
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newGlobalRolePrimitives(ctx.logger, connectArgoCd)
  );
