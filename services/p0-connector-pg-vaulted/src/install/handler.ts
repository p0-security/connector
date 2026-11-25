import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
} from "@p0security/connector-core";

import {
  listGrantableRoles,
  withPgClient,
} from "../accesses/common/handler.ts";
import { readManagerCredential } from "../clouds/aws-rds.ts";
import { toConnectorError } from "../postgres/errors.ts";
import {
  type InstallValidation,
  type PgVaultedInstallStep,
  installContext,
} from "./definition.ts";

/** A failed check. It never carries the driver's message, which can quote
 * the server. */
const failedAt = (
  step: PgVaultedInstallStep,
  host: string,
  { type, message, payload }: ConnectorError["data"]
) => new ConnectorError({ type, message, payload: { ...payload, step, host } });

/**
 * Lets the installer confirm the connector can manage a target, and write
 * nothing. It runs the `manager_secret` and `sign_in` checks of
 * `PG_VAULTED_INSTALL_STEPS`, signing in as the username the manager secret
 * holds, then returns the grantable roles.
 */
export const router = (t: AnyConnectorTRPCInstance) => {
  const { router, procedure } = t;

  return router({
    get: procedure
      .input(installContext.parse)
      .query(async ({ input, ctx }): Promise<InstallValidation> => {
        const { host, port, database, managerSecret } = input.target;
        const logger = ctx.logger.child({ host, port, database });
        let username: string;
        try {
          ({ username } = await readManagerCredential(managerSecret, host));
        } catch {
          throw failedAt("manager_secret", host, {
            type: "unknown",
            message:
              "The connector could not read the manager secret, its value is not a JSON object with a username, a password and a host, or its host is not the target's.",
            payload: {},
          });
        }
        return await withPgClient(
          {
            p0User: username,
            host,
            port,
            database,
            managerSecret,
            cloud: "rds",
          },
          logger,
          async (client) => {
            try {
              await client.raw("SELECT 1");
            } catch (error) {
              throw failedAt("sign_in", host, toConnectorError(error).data);
            }
            const roles = await listGrantableRoles(client, logger);
            return { grantableRoles: roles.map(({ key }) => key) };
          }
        );
      }),
  });
};
