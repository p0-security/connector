import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
} from "@p0security/connector-core";

import type { Pause } from "../../miro/client.ts";
import type { RequestContext, UserBody } from "./definition.ts";
import { spec } from "./definition.ts";
import { list } from "./list.ts";
import { setBoardPolicies } from "./policies.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

/**
 * The Miro `board` access: the requester's own Miro user's role on one
 * board, raised for the grant and lowered back at its end (policies.ts).
 *
 * The user is an existing member of the team, whose user id P0 found with
 * the `member` lister when the request was made and sends in the user
 * body. Nothing is looked up here, and no team member is ever invited.
 *
 * Exported separately from {@link router} so the primitives can be driven
 * against a Miro double, with a `pause` that doesn't wait.
 */
export const newBoardPrimitives = (
  logger: Logger,
  pause?: Pause
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  // A Miro user id can't carry a P0 marker, so there's no namespace to check
  // it against.
  validation: () => ({ user: null }),

  /**
   * The body's member id, without calling Miro. A grant checks the member
   * again in `setPoliciesForUser`, and a revoke runs this too, where nothing
   * may stand between P0 and taking access away. Never `null`: the
   * framework's `provisionUser` would then call `createUser`.
   */
  getUser: async (_context: RequestContext, { memberId }: UserBody) => memberId,

  /** Refuses. `getUser` always answers, and P0 never invites. */
  createUser: async ({ requestId }: RequestContext): Promise<never> => {
    throw new ConnectorError({
      message:
        "P0 asked the Miro connector to invite a Miro user, which it never does. Contact P0 support.",
      payload: { requestId },
      type: "unknown",
    });
  },

  /**
   * Does nothing, on purpose. P0's revoke calls it after
   * `setPoliciesForUser` has taken back what P0 gave, and the member was in
   * the team before P0, so removing them would take more than P0 gave.
   */
  deleteUser: async ({ requestId }: RequestContext, memberId: string) => {
    logger.debug(
      { memberId, requestId },
      "deleteUser does nothing: the member was in the team before P0"
    );
  },

  setPoliciesForUser: (context, memberId, _user, policies) =>
    setBoardPolicies({
      context,
      logger,
      memberId,
      policies,
      ...(pause === undefined ? {} : { pause }),
    }),

  list: (query) => list(logger, query),
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newBoardPrimitives(ctx.logger)
  );
