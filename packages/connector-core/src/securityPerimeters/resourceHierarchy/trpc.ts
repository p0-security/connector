import {
  withRouteLogging,
  withSecurityPerimeter,
} from "../common/middleware.ts";
import type {
  AnyConnectorTRPCInstance,
  ConnectorContext,
} from "../common/trpc.ts";
import type { ResourceHierarchyConnectorPrimitives } from "./implementation.ts";
import { buildResourceHierarchySecurityPerimeter } from "./implementation.ts";
import type { ResourceHierarchyParsers } from "./parsers.ts";
import type { ResourceHierarchySchema } from "./schema.ts";

export type ResourceHierarchyRouter<Schema extends ResourceHierarchySchema> =
  ReturnType<typeof newResourceHierarchyRouter<Schema>>;

/**
 * Wraps the {@link ResourceHierarchySecurityPerimeter} with input validation on the deployed connector using a set of parsers
 *
 * @summary Wraps the {@link ResourceHierarchySecurityPerimeter} with input validation on the deployed connector using a set of parsers
 * @category High-Level
 */
export const newResourceHierarchyRouter = <
  Schema extends ResourceHierarchySchema,
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
>(
  t: TRPCInstance,
  parsers: ResourceHierarchyParsers<Schema>,
  newMethods: (
    ctx: ConnectorContext
  ) => ResourceHierarchyConnectorPrimitives<Schema>
) => {
  const { router } = t;
  const procedure = withSecurityPerimeter(
    withRouteLogging(t.procedure),
    (ctx) => buildResourceHierarchySecurityPerimeter(newMethods(ctx))
  );
  const p = parsers;

  // prettier-ignore
  return router({
    provisionUser: procedure.input(p.provisionUser).mutation(({ input, ctx }) => ctx.perimeter.provisionUser(input)),
    identifyUser: procedure.input( p.identifyUser).mutation(({ input, ctx }) => ctx.perimeter.identifyUser(input)),
    createAccessResource: procedure.input(p.createAccessResource).mutation(({ input, ctx }) => ctx.perimeter.createAccessResource(input)),
    deleteAccessResource: procedure.input(p.deleteAccessResource).mutation(({ input, ctx }) => ctx.perimeter.deleteAccessResource(input)),
    addPoliciesToResource: procedure.input(p.addPoliciesToResource).mutation(({ input, ctx }) => ctx.perimeter.addPoliciesToResource(input)),
    removePoliciesFromResource: procedure.input(p.removePoliciesFromResource).mutation(({ input, ctx }) => ctx.perimeter.removePoliciesFromResource(input)),
    bindAccessResource: procedure.input(p.bindAccessResource).mutation(({ input, ctx }) => ctx.perimeter.bindAccessResource(input)),
    unbindAccessResource: procedure.input(p.unbindAccessResource).mutation(({ input, ctx }) => ctx.perimeter.unbindAccessResource(input)),
    list: procedure.input(p.list).query(({ input, ctx }) => ctx.perimeter.list(input))
  });
};
