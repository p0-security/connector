import { ConnectorError, throwAssertNever } from "@p0security/connector-core";
import {
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  type SecretValue,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/secret-manager-client";

import type { ClientSecret } from "./credentials.ts";

// What the connector's identity needs on the secret. On Google the shared
// client reads the version's payload and then its metadata, so it needs both.
const READ_GRANT: Record<ClientSecret["manager"], string> = {
  aws: "secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key",
  gcp: "secretmanager.versions.access and secretmanager.versions.get on that secret",
};

const providerConfig = (pointer: ClientSecret): SecretManagerProviderConfig => {
  switch (pointer.manager) {
    case "aws":
      return { provider: "aws", region: pointer.region };
    case "gcp":
      return { provider: "gcp", projectId: pointer.projectId };
    default:
      throw throwAssertNever(pointer);
  }
};

/** The client secret, and the version of the secret it was read from. */
export type ClientSecretValue = { secret: string; version: string };

/**
 * Reads the Management API client's secret from the customer's own secret
 * manager, with the connector's own cloud identity.
 *
 * The secret goes back to the caller and nowhere else: not into a log line
 * and not into an error.
 */
export const getClientSecret = async (
  pointer: ClientSecret
): Promise<ClientSecretValue> => {
  const { manager, secretId } = pointer;
  const secrets = await createSecretManagerClient(providerConfig(pointer));
  let stored: SecretValue;
  try {
    // `SecretRef` brands the provider's own name for a secret, which is what
    // the customer gave P0.
    stored = await secrets.getSecretValue({ ref: secretId as SecretRef });
  } catch (error) {
    if (error instanceof SecretNotFoundError) {
      throw new ConnectorError({
        type: "object_not_found",
        message: `The connector couldn't find the Auth0 client secret ${secretId}. Check the client secret in the P0 install, and that the secret still exists.`,
        payload: { query: secretId, manager },
      });
    }
    if (error instanceof UnauthorizedError) {
      throw new ConnectorError({
        type: "insufficient_privileges",
        message: `The connector isn't allowed to read the Auth0 client secret ${secretId}. Grant the connector's identity ${READ_GRANT[manager]}.`,
        payload: { secretId, manager },
      });
    }
    throw error;
  }
  const { value, version } = stored;
  // A secret written with `echo` or a heredoc ends in a newline.
  const secret = (
    typeof value === "string" ? value : value.toString("utf8")
  ).trim();
  if (secret === "") {
    // Not a `validation_error`: the requestor can't fix the install.
    throw new ConnectorError({
      type: "insufficient_privileges",
      message: `The Auth0 client secret ${secretId} is empty. Store the Management API application's client secret in it.`,
      payload: { secretId, manager },
    });
  }
  return { secret, version: version.ref };
};
