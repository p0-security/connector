import {
  type ConnectorContext,
  ConnectorError,
  type CustomAppConnectorActions,
  type Logger,
  type RequestContext,
  type UserId,
} from "@p0security/connector-sdk";

import { POLICY_CATALOGUE, isKnownPolicy } from "./catalogue.ts";

/**
 * Prefix stamped onto every user this connector provisions in the application.
 */
const P0_PREFIX = "p0_";

/**
 * Maps the principal P0 sends - for example, the requester's email
 * address - to this application's own identifier for their account.
 */
const userIdFor = (principal: string): UserId => `${P0_PREFIX}${principal}`;

/**
 * Whether an identifier names a user this connector provisioned.
 *
 * Returning `false` from a validator is enough to abort the action P0 asked
 * for.
 */
const isP0Managed = (userId: UserId): boolean => userId.startsWith(P0_PREFIX);

/**
 * Builds the seven actions P0 calls, once per request.
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
     * Whether P0 may act on a principal — the email address P0 knows the
     * requester by, before this application has named an account for them.
     *
     * The SDK calls this before `getUser` and `createUser`, and abandons the
     * request if it says no, so neither action needs a check of its own.
     *
     * This application derives its account names from the principal rather
     * than using it directly, so the check applies the same mapping
     * `createUser` does before asking. A connector whose accounts *are* the
     * principals it receives has nothing to map, and can hand the same
     * function to both validators.
     */
    validatePrincipal: async (context, principal) => {
      const log = forRequest(context);
      log.info({ principal }, "validatePrincipal invoked");
      return isP0Managed(userIdFor(principal));
    },

    /**
     * Whether P0 may act on a user id — the `p0_`-prefixed name this
     * application returned from `createUser`, not the principal P0 sent.
     *
     * The SDK calls this before `deleteUser` and `setPoliciesForUser`. It is
     * the check that keeps a revocation away from an account P0 never created,
     * which is why this example refuses rather than returning `async () =>
     * true` as an application with nowhere to put a marker would have to.
     *
     * Both validators are `async`: a real connector is free to ask the target
     * system — for a tag, a group membership, the OU a user lives in — instead
     * of only inspecting the string.
     */
    validateUserId: async (context, userId) => {
      const log = forRequest(context);
      log.info({ userId }, "validateUserId invoked");
      return isP0Managed(userId);
    },

    /**
     * Returns the existing P0-managed user, or `null` if P0 should create one.
     *
     * P0 calls this before `createUser` on every grant, so it must be safe to
     * call repeatedly and must not have side effects.
     */
    getUser: async (context, userBody) => {
      const log = forRequest(context);
      log.info({ principal: userBody.principal }, "getUser invoked");
      return null;
    },

    /**
     * Provisions a P0-managed user and returns the identifier this application
     * knows them by. Every later action receives that identifier back.
     */
    createUser: async (context, userBody) => {
      const log = forRequest(context);
      const userId = userIdFor(userBody.principal);
      log.info({ principal: userBody.principal, userId }, "createUser invoked");
      return userId;
    },

    /**
     * Removes a P0-managed user, at grant expiry or on explicit revocation.
     *
     * If your application cannot or should not delete users — because the
     * account predates P0, or deletion cascades to owned objects — leave the
     * account in place. A no-op is a valid implementation.
     */
    deleteUser: async (context, userId) => {
      const log = forRequest(context);
      log.info({ userId }, "deleteUser invoked");
    },

    /**
     * Replaces the user's entire policy set with `policies`.
     *
     * This is a set, not a delta: P0 sends the full list the user should hold
     * after the call, and an empty array means "revoke everything".
     */
    setPoliciesForUser: async (context, userId, policies) => {
      const log = forRequest(context);
      log.info({ userId, policies }, "setPoliciesForUser invoked");

      const unknown = policies.filter((policy) => !isKnownPolicy(policy));
      if (unknown.length > 0) {
        throw new ConnectorError({
          type: "object_not_found",
          message: `Unknown ${unknown.length === 1 ? "policy" : "policies"}: ${unknown.join(", ")}`,
          payload: { userId, unknownPolicies: unknown.join(",") },
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
