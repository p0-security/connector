import {
  withRouteLogging,
  withSecurityPerimeter,
} from "../common/middleware.ts";
import type {
  AnyConnectorTRPCInstance,
  ConnectorContext,
} from "../common/trpc.ts";
import { buildSecretManagementSecurityPerimeter } from "./implementation.ts";
import type { SecretManagementConnectorPrimitives } from "./implementation.ts";
import type { SecretManagementParsers } from "./parsers.ts";
import type { SecretManagementSchema } from "./schema.ts";

export type SecretManagementRouter<Schema extends SecretManagementSchema> =
  ReturnType<typeof newSecretManagementRouter<Schema>>;

/**
 * Wraps the {@link SecretManagementSecurityPerimeter} with input validation on the deployed connector using a set of parsers
 */
export const newSecretManagementRouter = <
  Schema extends SecretManagementSchema,
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
>(
  t: TRPCInstance,
  parsers: SecretManagementParsers<Schema>,
  newMethods: (
    ctx: ConnectorContext
  ) => SecretManagementConnectorPrimitives<Schema>
) => {
  const { router } = t;
  const procedure = withSecurityPerimeter(
    withRouteLogging(t.procedure),
    (ctx) => buildSecretManagementSecurityPerimeter(newMethods(ctx))
  );
  const p = parsers;

  return router({
    listSecrets: procedure
      .input(p.listSecrets)
      .query(({ ctx, input }) => ctx.perimeter.listSecrets(input)),
    getSecretMetadata: procedure
      .input(p.getSecretMetadata)
      .query(({ ctx, input }) => ctx.perimeter.getSecretMetadata(input)),
    createNewVersion: procedure
      .input(p.createNewVersion)
      .mutation(({ ctx, input }) => ctx.perimeter.createNewVersion(input)),
    disableVersion: procedure
      .input(p.disableVersion)
      .mutation(({ ctx, input }) => ctx.perimeter.disableVersion(input)),
    deleteVersion: procedure
      .input(p.deleteVersion)
      .mutation(({ ctx, input }) => ctx.perimeter.deleteVersion(input)),
    getInstallValidation: procedure
      .input(p.getInstallValidation)
      .query(({ ctx, input }) => ctx.perimeter.getInstallValidation(input)),
  });
};
