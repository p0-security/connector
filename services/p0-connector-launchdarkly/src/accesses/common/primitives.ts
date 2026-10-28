import { ConnectorError, type Logger } from "@p0security/connector-core";

import type { BaseRequestContext, UserBody } from "./definition.ts";

/**
 * The user primitives every access shares. The user is an existing
 * LaunchDarkly member, whose `_id` P0 resolved from the principal's email
 * and sends in the user body. Nothing is looked up, and no member is ever
 * invited or removed.
 */
export const memberPrimitives = (logger: Logger) => ({
  // A member's `_id` can't carry a P0 marker, so there's no namespace to
  // check it against.
  validation: () => ({ user: null }),

  /**
   * The body's member id, without calling LaunchDarkly. A grant checks the
   * member again in `setPoliciesForUser`, and a revoke runs this too, where
   * nothing may stand between P0 and taking access away. Never `null`: the
   * framework's `provisionUser` would then call `createUser`.
   */
  getUser: async (_context: BaseRequestContext, { memberId }: UserBody) =>
    memberId,

  /** Refuses. `getUser` always answers, and P0 never invites members. */
  createUser: async ({ requestId }: BaseRequestContext): Promise<never> => {
    throw new ConnectorError({
      message:
        "P0 asked the LaunchDarkly connector to invite a LaunchDarkly member, which it never does. Contact P0 support.",
      payload: { requestId },
      type: "unknown",
    });
  },

  /**
   * Does nothing, on purpose. P0's revoke calls it after
   * `setPoliciesForUser` has taken back what P0 gave, and the member was
   * there before P0, so removing them would take more than P0 gave.
   */
  deleteUser: async ({ requestId }: BaseRequestContext, memberId: string) => {
    logger.debug(
      { memberId, requestId },
      "deleteUser does nothing: the member was there before P0"
    );
  },
});
