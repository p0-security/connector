import {
  withRouteLogging,
  withSecurityPerimeter,
} from "../common/middleware.ts";
import type {
  AnyConnectorTRPCInstance,
  ConnectorContext,
} from "../common/trpc.ts";
import type { ResourceRootConnectorPrimitives } from "./implementation.ts";
import { buildResourceRootSecurityPerimeter } from "./implementation.ts";
import type { ResourceRootParsers } from "./parsers.ts";
import type { ResourceRootSchema } from "./schema.ts";

export type ResourceRootRouter<Schema extends ResourceRootSchema> = ReturnType<
  typeof newResourceRootRouter<Schema>
>;

/**
 * Wraps the {@link ResourceRootSecurityPerimeter} with input validation on the deployed connector using a set of parsers
 *
 * @summary Wraps the {@link ResourceRootSecurityPerimeter} with input validation on the deployed connector using a set of parsers
 * @category High-Level
 */
export const newResourceRootRouter = <
  Schema extends ResourceRootSchema,
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
>(
  t: TRPCInstance,
  parsers: ResourceRootParsers<Schema>,
  newMethods: (ctx: ConnectorContext) => ResourceRootConnectorPrimitives<Schema>
) => {
  const { router } = t;
  const procedure = withSecurityPerimeter(
    withRouteLogging(t.procedure),
    (ctx) => buildResourceRootSecurityPerimeter(newMethods(ctx))
  );
  const p = parsers;

  // prettier-ignore
  return router({
    provisionUser: procedure.input(p.provisionUser).mutation(({ input, ctx }) => ctx.perimeter.provisionUser(input)),
    identifyUser: procedure.input( p.identifyUser).mutation(({ input, ctx }) => ctx.perimeter.identifyUser(input)),
    deleteUser: procedure.input(p.deleteUser).mutation(({ input, ctx }) => ctx.perimeter.deleteUser(input)),
    setPoliciesForUser: procedure.input(p.setPoliciesForUser).mutation(({ input, ctx }) => ctx.perimeter.setPoliciesForUser(input)),
    list: procedure.input(p.list).query(({ input, ctx }) => ctx.perimeter.list(input))
  });
};
