import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
} from "@p0security/connector";

import { mysqlClientParams } from "../accesses/role/definition.ts";
import { newClient } from "../dbclient.ts";

const getInstallValidation = async (
  client: Awaited<ReturnType<typeof newClient>>
) => {
  const canConnect = await client
    .raw("SELECT 1")
    .then(() => true)
    .catch(() => false);
  if (!canConnect) {
    return {
      canConnect: false,
      schemaPrivileges: [],
      globalPrivileges: [],
    };
  }
  const schemaPrivileges = (
    await client
      .select<
        any,
        {
          PRIVILEGE_TYPE: string;
          TABLE_SCHEMA: string;
          IS_GRANTABLE: string;
        }[]
      >(["PRIVILEGE_TYPE", "TABLE_SCHEMA", "IS_GRANTABLE"])
      .from("information_schema.SCHEMA_PRIVILEGES")
      .where(
        "GRANTEE",
        client.raw(`CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")`)
      )
  ).map(({ IS_GRANTABLE, ...rest }) => ({
    IS_GRANTABLE: IS_GRANTABLE.toLowerCase().startsWith("y"),
    ...rest,
  }));
  const globalPrivileges = (
    await client
      .select<
        any,
        {
          PRIVILEGE_TYPE: string;
          IS_GRANTABLE: string;
        }[]
      >(["PRIVILEGE_TYPE", "IS_GRANTABLE"])
      .from("information_schema.USER_PRIVILEGES")
      .where(
        "GRANTEE",
        client.raw(`CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")`)
      )
  ).map(({ IS_GRANTABLE, ...rest }) => ({
    IS_GRANTABLE: IS_GRANTABLE.toLowerCase().startsWith("y"),
    ...rest,
  }));
  return { canConnect: true, schemaPrivileges, globalPrivileges };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router, procedure } = t;

  return router({
    get: procedure
      .input(mysqlClientParams.parse)
      .query(async ({ input, ctx }) => {
        const { p0User, host, port, cloud } = input;
        const logger = ctx.logger.child({
          user: p0User,
          host,
          port,
          cloud,
        });
        const client = await newClient({ host, port, user: p0User }, cloud);
        try {
          const validation = await getInstallValidation(client);
          if (!validation.canConnect) {
            logger.warn(
              { canConnect: false },
              "could not connect to MySQL instance"
            );
          } else {
            logger.debug(
              {
                canConnect: true,
                schemaPrivileges: validation.schemaPrivileges,
                globalPrivileges: validation.globalPrivileges,
              },
              "validated network connectivity to MySQL instance"
            );
          }
          return validation;
        } catch (error) {
          logger.error({ error }, "error during install validation");
          throw new ConnectorError({
            type: "unknown",
            message: "Unknown error during install validation",
            payload: {},
          });
        } finally {
          client
            .destroy()
            .catch((error) =>
              logger.error({ error }, "failed to close MySQL client")
            );
        }
      }),
  });
};
