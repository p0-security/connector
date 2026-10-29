import { ConnectorError, type Logger } from "@p0security/connector-core";
import {
  type SecretManagerClient,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";

import type { InstanceContext } from "./accesses/model/definition.ts";
import { type LookerSession, login, logout } from "./looker/looker-api.ts";
import { fetchAdminKey } from "./secrets.ts";

export type InstanceClients = {
  secretManager: SecretManagerClient;
  looker: LookerSession;
};

const newSecretManager = async (log: Logger, context: InstanceContext) => {
  const { manager, projectId } = context.secrets;
  try {
    return await createSecretManagerClient({ provider: manager, projectId });
  } catch (error) {
    log.warn({ manager, error }, "failed to create the secret manager client");
    throw new ConnectorError({
      type: "validation_error",
      message: "Invalid secret manager",
      payload: { manager },
    });
  }
};

/**
 * Runs `run` with the secret manager, and with a Looker session that is signed
 * in with the Admin key. Signs out afterwards.
 */
export const withInstance = async <T>(
  log: Logger,
  context: InstanceContext,
  run: (clients: InstanceClients) => Promise<T>
): Promise<T> => {
  const secretManager = await newSecretManager(log, context);
  const adminKey = await fetchAdminKey(
    secretManager,
    context.secrets.adminKeySecretId
  );
  const looker = await login(context.baseUrl, adminKey);
  try {
    return await run({ secretManager, looker });
  } finally {
    // The Admin token would otherwise stay valid for about an hour.
    await logout(looker).catch((error: unknown) =>
      log.warn(
        { error },
        "failed to sign out of Looker, so the token stays valid until it expires"
      )
    );
  }
};
