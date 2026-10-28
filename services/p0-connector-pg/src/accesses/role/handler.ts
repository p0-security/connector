import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  newResourceHierarchyRouter,
  throwAssertNever,
} from "@p0security/connector";

import { ident } from "../../sql/identifier.ts";
import {
  assertGrantableRole,
  assertNotConnectorRole,
  listDatabases,
  listGrantableRoles,
  newCommonPgPrimitives,
  withMethodContext,
  withPgClient,
} from "../common/handler.ts";
import { spec } from "./definition.ts";

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceHierarchyRouter(t, spec, (ctx: ConnectorContext) => {
    return {
      ...newCommonPgPrimitives(ctx),

      async addPolicyToResource(context, resourceBody, policy) {
        return await withMethodContext(
          ctx,
          context,
          { resourceBody, policy },
          async ({ client, logger }) => {
            await assertNotConnectorRole(client, context, [resourceBody]);
            const type = policy.type;
            switch (type) {
              case "role": {
                await assertGrantableRole(client, policy.rolename);
                await client.raw(
                  `GRANT ${ident(policy.rolename)} TO ${ident(resourceBody)}`
                );
                break;
              }
              default: {
                throw throwAssertNever(type);
              }
            }
            logger.info("granted policy to Postgres resource");
          }
        );
      },

      async removePolicyFromResource(context, resourceBody, policy) {
        return await withMethodContext(
          ctx,
          context,
          { resourceBody, policy },
          async ({ client, logger }) => {
            await assertNotConnectorRole(client, context, [resourceBody]);
            const type = policy.type;
            switch (type) {
              case "role": {
                await client.raw(
                  `REVOKE ${ident(policy.rolename)} FROM ${ident(resourceBody)}`
                );
                break;
              }
              default: {
                throw throwAssertNever(type);
              }
            }
            logger.info("revoked policy from Postgres resource");
          }
        );
      },

      async list({ type, context }) {
        const { host, port } = context;
        const logger = ctx.logger.child({ host, port, type });
        return await withPgClient(context, logger, async (client) => {
          switch (type) {
            case "database":
              return await listDatabases(client, logger);
            case "role":
              return await listGrantableRoles(client, logger);
            default:
              throw throwAssertNever(type);
          }
        });
      },
    };
  });
