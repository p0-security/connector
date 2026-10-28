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

import { assertAllowedEmail } from "../../allowlist.ts";
import {
  type ConnectHarbor,
  type HarborUserAdmin,
  connectHarbor,
} from "../../harbor/client.ts";
import { callHarbor } from "../../harbor/errors.ts";
import { duplicateEmail } from "../../refusals.ts";
import { hostOf } from "../project-role/definition.ts";
import { type HarborAdminState, spec } from "./definition.ts";
import { setPolicies } from "./policies.ts";

/** The access's types, as its schemas infer them. */
export type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

type ListerQuery = ResourceSchema["ListerQuery"];
type ListerResponse = ResourceSchema["ListerResponse"];

/** A user's admin state, as the lister reports it. */
export const adminStateOf = ({
  sysadminFlag,
  adminRoleInAuth,
}: Pick<
  HarborUserAdmin,
  "adminRoleInAuth" | "sysadminFlag"
>): HarborAdminState => {
  if (sysadminFlag) return adminRoleInAuth ? "flag_and_auth" : "flag";
  return adminRoleInAuth ? "auth" : "none";
};

/**
 * The admin state of the Harbor user whose email is the principal's: `[]`
 * for none, or `[{ key: <user id>, value: <HarborAdminState> }]`. It reads as
 * the member lister does: the domain allowlist first, then every page of
 * Harbor's substring matches, keeping the exact ones, and two or more is the
 * `duplicate_email` refusal.
 */
const findAdminState = async (
  { context, email }: Extract<ListerQuery, { type: "admin-state" }>,
  logger: Logger,
  connect: ConnectHarbor
): Promise<ListerResponse> => {
  assertAllowedEmail(email, logger);
  const host = hostOf(context);
  const harbor = await connect(context, logger);
  const users = await callHarbor(
    () => harbor.findUserAdminsByEmail(email),
    host
  );
  if (users.length > 1) throw duplicateEmail({ host, email, users });
  return users.map((user) => ({
    key: String(user.userId),
    value: adminStateOf(user),
  }));
};

/**
 * The Harbor `systemAdmin` access: Harbor's system administrator flag on one
 * user, granted just in time and taken back at expiry.
 *
 * Every call is the Harbor admin user's, from the instance's admin
 * credential: Harbor lets only a system administrator change the flag
 * (policies.ts).
 *
 * Exported separately from {@link router} so the primitives can be driven
 * against a Harbor double.
 */
export const newSystemAdminPrimitives = (
  logger: Logger,
  connect: ConnectHarbor
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  // The user is Harbor's own numeric user id, which can't carry a P0
  // marker, so there's nothing to validate a user's namespace against.
  validation: () => ({ user: null }),
  /**
   * The user body's Harbor user id, without calling Harbor, as for a project
   * role: a grant checks it again, and a revoke must not depend on a read.
   */
  getUser: async (_context, { userId }) => userId,

  /** Refuses: the connector never creates Harbor users. */
  createUser: async ({ requestId }) => {
    throw new ConnectorError({
      type: "unknown",
      message:
        "P0 asked the Harbor connector to create a Harbor user, which it never does.",
      payload: { requestId },
    });
  },

  /**
   * A no-op, and this is load-bearing: P0's revoke calls it after
   * `setPoliciesForUser` has cleared the flag, and the user is the
   * customer's.
   */
  deleteUser: async ({ requestId }, userId) => {
    logger.debug(
      { requestId, userId },
      "deleteUser is a no-op; the revoke clears the flag"
    );
  },

  setPoliciesForUser: (context, userId, _user, policies) =>
    setPolicies({ connect, logger, context, userId, policies }),

  list: async (query) => {
    switch (query.type) {
      case "admin-state":
        return await findAdminState(query, logger, connect);
      default:
        throw throwAssertNever(query.type);
    }
  },
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newSystemAdminPrimitives(ctx.logger, connectHarbor)
  );
