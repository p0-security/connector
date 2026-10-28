import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
} from "@p0security/connector-core";

import { pgClientParams } from "../accesses/common/definition.ts";
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
      grantedRoles: [],
    };
  }

  // Use SESSION_USER (not CURRENT_USER) so we check roles granted to the login
  // identity, even if a cloud-specific pool hook has changed the active role via SET ROLE.
  const result = await client.raw<{ rows: { role_name: string }[] }>(
    `SELECT r.rolname AS role_name
     FROM pg_auth_members m
     JOIN pg_roles r ON r.oid = m.roleid
     JOIN pg_roles u ON u.oid = m.member
     WHERE u.rolname = SESSION_USER`
  );
  const grantedRoles = result.rows.map(({ role_name }) => role_name);
  return { canConnect: true, grantedRoles };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router, procedure } = t;

  return router({
    get: procedure.input(pgClientParams.parse).query(async ({ input, ctx }) => {
      const { p0User, host, port, database, cloud } = input;
      const logger = ctx.logger.child({
        user: p0User,
        host,
        port,
        database,
        cloud,
      });
      const client = await newClient(
        { host, port, database, user: p0User },
        cloud
      );
      try {
        const validation = await getInstallValidation(client);
        if (!validation.canConnect) {
          logger.warn(
            { canConnect: false },
            "could not connect to Postgres instance"
          );
        } else {
          logger.debug(
            { canConnect: true, grantedRoles: validation.grantedRoles },
            "validated network connectivity to Postgres instance"
          );
        }
        return validation;
      } catch (error) {
        logger.error({ error }, "error during Postgres install validation");
        throw new ConnectorError({
          type: "unknown",
          message: "Unknown error during install validation",
          payload: {},
        });
      } finally {
        client
          .destroy()
          .catch((error) =>
            logger.error({ error }, "failed to close Postgres client")
          );
      }
    }),
  });
};
