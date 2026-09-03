import {
  type ConnectorContext,
  ConnectorError,
  type CustomAppConnectorActions,
  type Logger,
  type RequestContext,
  type UserBody,
} from "@p0security/connector-sdk";

import { POLICY_CATALOGUE, isKnownPolicy } from "./catalogue.ts";

/**
 * Prefix stamped onto every user this connector provisions in the application.
 */
const P0_PREFIX = "p0_";

/**
 * Maps the principal P0 sends - for example, the requester's email
 * address - to this application's own identifier for their account.
 *
 * Every action receives the principal rather than an application-side id, so
 * each one applies this mapping for itself. That is also what confines this
 * connector to the `p0_` namespace: no action can be pointed at an account
 * outside it, because no action is handed an account name to begin with.
 */
const accountFor = (user: UserBody): string => `${P0_PREFIX}${user.principal}`;

/**
 * Builds the six actions P0 calls, once per request.
 *
 * `ctx.logger` arrives already tagged with the tRPC route being served (e.g.
 * `app.accesses.access.provisionUser`), so anything logged here is traceable
 * to the call that produced it. The request id and application id live in the
 * per-action `context` argument, so each action folds them into a child logger
 * of its own.
 */
export const newActions = (
  ctx: ConnectorContext
): CustomAppConnectorActions => {
  const { logger } = ctx;

  // A real connector constructs its target-system client here. That is why
  // `actions` is a factory rather than a plain object: something holding a
  // connection, a short-lived token, or this logger has somewhere to live, and
  // is rebuilt per request rather than shared across them.

  const forRequest = (context: RequestContext): Logger =>
    logger.child({ requestId: context.requestId, appId: context.appId });

  return {
    /**
     * Whether P0 may act on a user — identified by the `principal`, the email
     * address P0 knows the requester by, possibly before this application has
     * an account for them.
     *
     * The SDK calls this before every other user-keyed action, and abandons
     * the request if it says no, so none of those actions needs a check of its
     * own. This example admits every principal, so it effectively opts out
     * of validation.
     */
    validateUser: async (context, user) => {
      const log = forRequest(context);
      log.info({ principal: user.principal }, "validateUser invoked");
      return true;
    },

    /**
     * Whether this application already has a P0-managed account for the
     * principal. `false` tells P0 to call `createUser`.
     *
     * P0 calls this before `createUser` on every grant, so it must be safe to
     * call repeatedly and must not have side effects.
     */
    userExists: async (context, user) => {
      const log = forRequest(context);
      log.info({ account: accountFor(user) }, "userExists invoked");
      return false;
    },

    /**
     * Provisions a P0-managed account for the principal.
     */
    createUser: async (context, user) => {
      const log = forRequest(context);
      log.info({ account: accountFor(user) }, "createUser invoked");
    },

    /**
     * Removes a P0-managed user, at grant expiry or on explicit revocation.
     *
     * If your application cannot or should not delete users — because the
     * account predates P0, or deletion cascades to owned objects — leave the
     * account in place. A no-op is a valid implementation.
     */
    deleteUser: async (context, user) => {
      const log = forRequest(context);
      log.info({ account: accountFor(user) }, "deleteUser invoked");
    },

    /**
     * Replaces the user's entire policy set with `policies`.
     *
     * This is a set, not a delta: P0 sends the full list the user should hold
     * after the call, and an empty array means "revoke everything".
     */
    setPoliciesForUser: async (context, user, policies) => {
      const log = forRequest(context);
      const account = accountFor(user);
      log.info({ account, policies }, "setPoliciesForUser invoked");

      const unknown = policies.filter((policy) => !isKnownPolicy(policy));
      if (unknown.length > 0) {
        throw new ConnectorError({
          type: "object_not_found",
          message: `Unknown ${unknown.length === 1 ? "policy" : "policies"}: ${unknown.join(", ")}`,
          payload: { account, unknownPolicies: unknown.join(",") },
        });
      }
    },

    /**
     * The entitlement catalogue behind P0's request-access picker.
     *
     * Note the shape of the argument: `list` receives a query rather than a
     * request context, because it runs while someone is browsing for access,
     * not while a grant is being provisioned.
     *
     * Currently, `query.type` can take on one value, which is `policy`
     */
    list: async (query) => {
      logger
        .child({ appId: query.appId })
        .info({ type: query.type }, "list invoked");
      return POLICY_CATALOGUE;
    },
  };
};
