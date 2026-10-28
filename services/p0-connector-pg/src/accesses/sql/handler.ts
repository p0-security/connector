import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  newResourceHierarchyRouter,
  throwAssertNever,
} from "@p0security/connector";

import { ident, privilegeKeyword, tableIdent } from "../../sql/identifier.ts";
import {
  assertGrantableRole,
  assertNotConnectorRole,
  listDatabases,
  newCommonPgPrimitives,
  withMethodContext,
  withPgClient,
} from "../common/handler.ts";
import { SCHEMA_PRIVILEGES, TABLE_PRIVILEGES, spec } from "./definition.ts";

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
              case "schema-privilege": {
                await client.raw(
                  `GRANT ${privilegeKeyword(policy.privilege, SCHEMA_PRIVILEGES)} ON SCHEMA ${ident(policy.schema)} TO ${ident(resourceBody)}`
                );
                break;
              }
              case "table-privilege": {
                await client.raw(
                  `GRANT ${privilegeKeyword(policy.privilege, TABLE_PRIVILEGES)} ON TABLE ${tableIdent(policy.table)} TO ${ident(resourceBody)}`
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
              case "schema-privilege": {
                await client.raw(
                  `REVOKE ${privilegeKeyword(policy.privilege, SCHEMA_PRIVILEGES)} ON SCHEMA ${ident(policy.schema)} FROM ${ident(resourceBody)}`
                );
                break;
              }
              case "table-privilege": {
                await client.raw(
                  `REVOKE ${privilegeKeyword(policy.privilege, TABLE_PRIVILEGES)} ON TABLE ${tableIdent(policy.table)} FROM ${ident(resourceBody)}`
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
            default:
              throw throwAssertNever(type);
          }
        });
      },
    };
  });
