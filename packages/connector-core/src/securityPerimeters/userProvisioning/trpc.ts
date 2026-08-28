import {
  withRouteLogging,
  withSecurityPerimeter,
} from "../common/middleware.ts";
import type {
  AnyConnectorTRPCInstance,
  ConnectorContext,
} from "../common/trpc.ts";
import type { UserProvisioningConnectorPrimitives } from "./implementation.ts";
import { buildUserProvisioningSecurityPerimeter } from "./implementation.ts";
import type { UserProvisioningParsers } from "./parsers.ts";
import type { UserProvisioningSchema } from "./schema.ts";

export type UserProvisioningRouter<Schema extends UserProvisioningSchema> =
  ReturnType<typeof newUserProvisioningRouter<Schema>>;

/**
 * Wraps the {@link UserProvisioningSecurityPerimeter} with input validation on the deployed connector using a set of parsers
 *
 * @summary Wraps the {@link UserProvisioningSecurityPerimeter} with input validation on the deployed connector using a set of parsers
 * @category High-Level
 */
export const newUserProvisioningRouter = <
  Schema extends UserProvisioningSchema,
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
>(
  t: TRPCInstance,
  parsers: UserProvisioningParsers<Schema>,
  newMethods: (
    ctx: ConnectorContext
  ) => UserProvisioningConnectorPrimitives<Schema>
) => {
  const { router } = t;
  const procedure = withSecurityPerimeter(
    withRouteLogging(t.procedure),
    (ctx) => buildUserProvisioningSecurityPerimeter(newMethods(ctx))
  );
  const p = parsers;
  // prettier-ignore
  return router({
    provision: procedure.input(p.provision).mutation(({ input, ctx }) => ctx.perimeter.provision(input)),
    identify: procedure.input(p.identify).mutation(({ input, ctx }) => ctx.perimeter.identify(input)),
    deprovision: procedure.input(p.deprovision).mutation(({ input, ctx }) => ctx.perimeter.deprovision(input)),
  });
};
