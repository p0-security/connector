import { ConnectorError, throwAssertNever } from "@p0security/connector";
import {
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/secret-manager-client";

import { API_KEY_SHAPE, type ApiKey, parseApiKey } from "./api-key.ts";
import type { SecretPointer } from "./credentials.ts";

// What the connector's identity needs on the secret. On Google the shared
// client reads the version's payload and then its metadata, so it needs both.
const READ_GRANT: Record<SecretPointer["manager"], string> = {
  aws: "secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key",
  gcp: "secretmanager.versions.access and secretmanager.versions.get on that secret",
};

const MANAGER_NAME: Record<SecretPointer["manager"], string> = {
  aws: "AWS Secrets Manager",
  gcp: "Google Secret Manager",
};

const providerConfig = (
  pointer: SecretPointer
): SecretManagerProviderConfig => {
  switch (pointer.manager) {
    case "aws":
      return { provider: "aws", region: pointer.region };
    case "gcp":
      return { provider: "gcp", projectId: pointer.projectId };
    default:
      throw throwAssertNever(pointer);
  }
};

/** The API key, and the version of the secret it was read from. */
export type ApiKeyValue = ApiKey & { version: string };

/** The secret's text as JSON, or `undefined` when it isn't JSON. */
const parseJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

/**
 * Reads the organization's API key from the customer's own secret manager,
 * with the connector's own cloud identity, and parses it strictly.
 *
 * The key goes back to the caller and nowhere else: not into a log line and
 * not into an error. Nothing of the pointer but its manager goes into either.
 * The secret's ID least of all: on AWS it is any string, so a key pasted where
 * the name goes would travel with the message.
 *
 * A secret that is empty or isn't the key's JSON is
 * `insufficient_privileges`, not a `validation_error`: the requestor can't
 * fix the install.
 */
export const readApiKey = async (
  pointer: SecretPointer
): Promise<ApiKeyValue> => {
  const { manager, secretId } = pointer;
  const managerName = MANAGER_NAME[manager];
  const failed = (type: "insufficient_privileges", message: string) =>
    new ConnectorError({ type, message, payload: { manager } });

  const secrets = await createSecretManagerClient(providerConfig(pointer));
  const { value, version } = await secrets
    // `SecretRef` brands the provider's own name for a secret, which is what
    // the customer gave P0.
    .getSecretValue({ ref: secretId as SecretRef })
    .catch((error: unknown) => {
      if (error instanceof SecretNotFoundError) {
        throw new ConnectorError({
          type: "object_not_found",
          message: `The connector couldn't find its ClickHouse Cloud API key secret in ${managerName}. Check that the secret still exists, and that the organization in P0 names it correctly. If the name is wrong, remove the organization in P0 and add it again.`,
          payload: { manager },
        });
      }
      if (error instanceof UnauthorizedError) {
        throw failed(
          "insufficient_privileges",
          `The connector isn't allowed to read its ClickHouse Cloud API key secret in ${managerName}. Grant the connector's identity ${READ_GRANT[manager]}.`
        );
      }
      throw error;
    });
  // AWS returns a text secret as a string. Google returns bytes.
  const text = (
    typeof value === "string" ? value : value.toString("utf8")
  ).trim();
  if (text === "") {
    throw failed(
      "insufficient_privileges",
      `The ClickHouse Cloud API key secret in ${managerName} is empty. Store ${API_KEY_SHAPE} as its value.`
    );
  }
  const parsed = parseApiKey(parseJson(text));
  if (!parsed.ok) {
    throw failed(
      "insufficient_privileges",
      `The ClickHouse Cloud API key secret in ${managerName} isn't the JSON the connector expects${parsed.problem}. Store ${API_KEY_SHAPE} as its value.`
    );
  }
  return { ...parsed.apiKey, version: version.ref };
};
