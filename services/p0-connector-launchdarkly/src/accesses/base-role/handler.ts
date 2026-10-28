import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
} from "@p0security/connector";

import { list } from "../common/list.ts";
import { type Pause, pauseFor, setMemberPolicies } from "../common/policies.ts";
import { memberPrimitives } from "../common/primitives.ts";
import { spec } from "./definition.ts";
import { grantBaseRole, revokeBaseRole } from "./policies.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

/**
 * The LaunchDarkly `base-role` access: the member's base role, Reader, Writer
 * or Admin, raised for the grant and lowered back at its end. A grant only
 * raises, and a revoke only lowers (policies.ts).
 *
 * Its `list` answers the queries every access shares (common/list.ts).
 * Exported separately from {@link router} so the primitives can be driven
 * against a LaunchDarkly double, with a `pause` that doesn't wait.
 */
export const newBaseRolePrimitives = (
  logger: Logger,
  pause: Pause = pauseFor
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  ...memberPrimitives(logger),
  setPoliciesForUser: (context, memberId, _user, policies) =>
    setMemberPolicies({
      access: "base-role",
      context,
      grant: (target, member) => grantBaseRole(target, member, context.role),
      held: policies.includes(context.role),
      logger,
      memberId,
      pause,
      revoke: (target) => revokeBaseRole(target, policies, context.priorRole),
    }),
  list: (query) => list(logger, query),
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newBaseRolePrimitives(ctx.logger)
  );
