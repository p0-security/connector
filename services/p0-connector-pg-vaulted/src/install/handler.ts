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
 * the server, only the connector's own words. */
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
        } catch (error) {
          if (error instanceof ConnectorError) {
            throw failedAt("manager_secret", host, error.data);
          }
          // Only the message, which names the failed check and never holds
          // the secret's value, so support can tell a host mismatch from a
          // secret that isn't JSON without a cause ever reaching the log.
          logger.warn(
            { reason: error instanceof Error ? error.message : "unknown" },
            "install check failed at manager_secret"
          );
          throw failedAt("manager_secret", host, {
            type: "unknown",
            message:
              "The connector could not read the manager secret, its value is not a JSON object with a username and a password, or the secret is not for the target's host.",
            payload: {},
          });
        }
        // Opening the client reads the secret again, and listing the roles is
        // the manager's first catalog read, so a failure in either counts as
        // the sign-in's.
        try {
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
              await client.raw("SELECT 1");
              const roles = await listGrantableRoles(client, logger);
              return { grantableRoles: roles.map(({ key }) => key) };
            }
          );
        } catch (error) {
          const failure = toConnectorError(error);
          // An unknown failure's error is kept only in the connector's own
          // log, so support can still tell, say, a pg_hba rule from a bug.
          if (failure.data.type === "unknown") {
            logger.warn({ error }, "install check failed at sign_in");
          }
          throw failedAt("sign_in", host, failure.data);
        }
      }),
  });
};
