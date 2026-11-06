import { ConnectorError, throwAssertNever } from "@p0security/connector-core";
import {
  type SecretManagerClient,
  type SecretManagerProviderConfig,
  type SecretRef,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";

import type { AdminTokenSecret } from "./secret-location.ts";

const secretManagerConfig = (
  secret: AdminTokenSecret
): SecretManagerProviderConfig => {
  switch (secret.manager) {
    case "aws":
      return { provider: "aws", region: secret.region };
    case "gcp":
      return { provider: "gcp", projectId: secret.projectId };
    default:
      throw throwAssertNever(secret);
  }
};

/** The customer's secret manager that holds the admin token. */
export const createSecretManager = async (secret: AdminTokenSecret) => {
  try {
    return await createSecretManagerClient(secretManagerConfig(secret));
  } catch {
    throw new ConnectorError({
      type: "validation_error",
      message: "Invalid secret manager",
      payload: { manager: secret.manager },
    });
  }
};

/** Reads the admin token that P0 uses to mint and revoke grant tokens. */
export const getAdminToken = async (
  secrets: SecretManagerClient,
  ref: SecretRef
): Promise<string> => {
  const { value } = await secrets.getSecretValue({ ref });
  // A pasted token often carries a trailing newline, which GitGuardian would
  // reject as an invalid key.
  const token = (
    typeof value === "string" ? value : value.toString("utf8")
  ).trim();
  if (!token) {
    // The value is never logged or returned.
    throw new ConnectorError({
      type: "validation_error",
      message:
        "The GitGuardian admin token secret is empty. Store the token as the secret's plain-text value.",
      payload: {},
    });
  }
  return token;
};
