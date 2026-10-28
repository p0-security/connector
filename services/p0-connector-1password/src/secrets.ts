import { ConnectorError, throwAssertNever } from "@p0security/connector";
import {
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  type SecretValue,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/secret-manager-client";

import type { TokenSecret } from "./accesses/share/definition.ts";

// What the connector's identity needs on the secret. On Google the shared
// client reads the version's payload and then its metadata, so it needs both.
const READ_GRANT: Record<TokenSecret["manager"], string> = {
  aws: "secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key",
  gcp: "secretmanager.versions.access and secretmanager.versions.get on that secret",
};

const providerConfig = (
  tokenSecret: TokenSecret
): SecretManagerProviderConfig => {
  switch (tokenSecret.manager) {
    case "aws":
      return { provider: "aws", region: tokenSecret.region };
    case "gcp":
      return { provider: "gcp", projectId: tokenSecret.projectId };
    default:
      throw throwAssertNever(tokenSecret);
  }
};

/** The service account token, and the version of the secret it was read from. */
export type ServiceAccountToken = { token: string; version: string };

/**
 * Reads the account's service account token from the customer's own secret manager,
 * with the connector's own cloud identity.
 *
 * The token goes back to the caller and nowhere else: not into a log line and
 * not into an error.
 */
export const getServiceAccountToken = async (
  tokenSecret: TokenSecret
): Promise<ServiceAccountToken> => {
  const { manager, secretId } = tokenSecret;
  const secrets = await createSecretManagerClient(providerConfig(tokenSecret));
  let secret: SecretValue;
  try {
    // `SecretRef` brands the provider's own name for a secret, which is what
    // the customer gave P0.
    secret = await secrets.getSecretValue({ ref: secretId as SecretRef });
  } catch (error) {
    if (error instanceof SecretNotFoundError) {
      throw new ConnectorError({
        type: "object_not_found",
        message: `The connector couldn't find the 1Password service account token secret ${secretId}. Check the token secret in the P0 install, and that the secret still exists.`,
        payload: { query: secretId, manager },
      });
    }
    if (error instanceof UnauthorizedError) {
      throw new ConnectorError({
        type: "insufficient_privileges",
        message: `The connector isn't allowed to read the 1Password service account token secret ${secretId}. Grant the connector's identity ${READ_GRANT[manager]}.`,
        payload: { secretId, manager },
      });
    }
    throw error;
  }
  const { value, version } = secret;
  // A secret written with `echo` or a heredoc ends in a newline.
  const token = (
    typeof value === "string" ? value : value.toString("utf8")
  ).trim();
  if (token === "") {
    // Not a `validation_error`: the requestor can't fix the install.
    throw new ConnectorError({
      type: "insufficient_privileges",
      message: `The 1Password service account token secret ${secretId} is empty. Store the account's service account token in it.`,
      payload: { secretId, manager },
    });
  }
  return { token, version: version.ref };
};
