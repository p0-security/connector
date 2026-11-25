import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
} from "@p0security/connector-core";

import {
  listGrantableRoles,
  withPgClient,
} from "../accesses/common/handler.ts";
import { readManagerCredential } from "../clouds/aws-rds.ts";
import { installContext } from "../context.ts";
import type { InstallValidation, PgVaultedInstallStep } from "./definition.ts";

/** A failed check. It carries the error's code, never its message, which
 * can quote the server. */
const failedAt = (
  step: PgVaultedInstallStep,
  host: string,
  message: string,
  code?: string
) =>
  new ConnectorError({
    type: "unknown",
    message,
    payload: { step, host, ...(code ? { code } : {}) },
  });

const codeOf = (error: unknown) =>
  typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined;

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
        const { username } = await readManagerCredential(managerSecret).catch(
          () => {
            throw failedAt(
              "manager_secret",
              host,
              "The connector could not read the manager secret, or its value is not a JSON object with a username and a password."
            );
          }
        );
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
            await client.raw("SELECT 1").catch((error: unknown) => {
              throw failedAt(
                "sign_in",
                host,
                "The manager could not sign in to the target's database.",
                codeOf(error)
              );
            });
            const roles = await listGrantableRoles(client, logger);
            return { grantableRoles: roles.map(({ key }) => key) };
          }
        );
      }),
  });
};
