import { ConnectorError, throwAssertNever } from "@p0security/connector-core";
import {
  type SecretManagerClient,
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  SecretVersionNotFoundError,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/secret-manager-client";

import type { InstallContext } from "./context.ts";
import { type SnowflakeSignIn, exportPrivateKey } from "./snowflake/client.ts";

export const secretRef = (id: string) => id as SecretRef;

// copy of `secretManagerConfig` in services/p0-connector-datadog-ai/src/accesses/permission/handler.ts
const secretManagerConfig = (
  secrets: InstallContext["secrets"]
): SecretManagerProviderConfig => {
  switch (secrets.manager) {
    case "aws":
      return { provider: "aws", region: secrets.region };
    case "gcp":
      return { provider: "gcp", projectId: secrets.projectId };
    default:
      throw throwAssertNever(secrets);
  }
};

export const createSecretManager = async (
  install: InstallContext
): Promise<SecretManagerClient> => {
  try {
    return await createSecretManagerClient(
      secretManagerConfig(install.secrets)
    );
  } catch {
    throw new ConnectorError({
      type: "validation_error",
      message: "Invalid secret manager",
      payload: { manager: install.secrets.manager },
    });
  }
};

// copy of `getConsumerSecret` in services/p0-connector-salesforce-ai/src/secrets.ts
/** Reads the connector's private key. The secret value is the PEM itself. */
export const getPrivateKey = async (
  secrets: SecretManagerClient,
  ref: SecretRef
): Promise<string> => {
  const { value } = await readPrivateKey(secrets, ref);
  const privateKey = typeof value === "string" ? value : value.toString("utf8");
  if (privateKey.trim().length === 0) {
    throw new ConnectorError({
      type: "validation_error",
      message: "The Snowflake connector private key secret is empty",
      payload: {},
    });
  }
  return privateKey;
};

/** Reads the key secret, mapping a failure to the error P0 shows, without
 * its cause. */
const readPrivateKey = async (secrets: SecretManagerClient, ref: SecretRef) => {
  try {
    return await secrets.getSecretValue({ ref });
  } catch (error) {
    const missing =
      error instanceof SecretNotFoundError ||
      error instanceof SecretVersionNotFoundError;
    throw new ConnectorError({
      type: missing
        ? "object_not_found"
        : error instanceof UnauthorizedError
          ? "insufficient_privileges"
          : "upstream_unavailable",
      message: missing
        ? "The Snowflake connector private key secret has no value"
        : "Failed to read the Snowflake connector private key secret",
      payload: { secretId: ref },
    });
  }
};

/** How the connector signs in to the install's account. The key is parsed
 * here, so a malformed key fails before any call to Snowflake. */
export const signInFor = async (
  install: InstallContext,
  secrets: SecretManagerClient
): Promise<SnowflakeSignIn> => ({
  account: install.account,
  username: install.connector.user,
  role: install.connector.role,
  warehouse: install.connector.warehouse,
  privateKey: exportPrivateKey(
    await getPrivateKey(secrets, secretRef(install.secrets.privateKeySecretId))
  ),
});
