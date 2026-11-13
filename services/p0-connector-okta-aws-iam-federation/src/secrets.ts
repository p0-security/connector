import {
  ConnectorError,
  type ConnectorErrorType,
  type Logger,
  throwAssertNever,
} from "@p0security/connector-core";
import {
  SecretManagerError,
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";
import { type KeyObject, createPrivateKey } from "node:crypto";
import { z } from "zod";

import type { SecretPointer } from "./account.ts";
import { type FailureFacts, failureFacts, renderFailure } from "./failure.ts";

// The reads and their error mapping are copies of the Cloudflare (AI)
// connector's (its src/secrets.ts). The value is a JWK, not a token.

type Vault = {
  config: SecretManagerProviderConfig;
  managerName: string;
  locationLabel: string;
  /** What the connector's identity needs on the secret. */
  readGrant: string;
};

const vaultOf = (pointer: SecretPointer): Vault => {
  switch (pointer.manager) {
    case "aws":
      return {
        config: { provider: "aws", region: pointer.region },
        locationLabel: "region",
        managerName: "AWS Secrets Manager",
        readGrant:
          "secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key",
      };
    case "gcp":
      return {
        config: { projectId: pointer.projectId, provider: "gcp" },
        locationLabel: "project",
        managerName: "Google Secret Manager",
        // The shared client also reads the version's metadata, which the
        // accessor role doesn't cover.
        readGrant:
          "roles/secretmanager.secretAccessor and roles/secretmanager.viewer on that secret",
      };
    default:
      throw throwAssertNever(pointer);
  }
};

const NETWORK_FAILURE_CODES: ReadonlySet<unknown> = new Set([
  "ENOTFOUND",
  "EAI_AGAIN",
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
]);

const typeOfUnmapped = ({
  name,
  code,
  status,
}: FailureFacts): ConnectorErrorType => {
  if (name === "ThrottlingException" || status === 429) return "rate_limited";
  if (
    NETWORK_FAILURE_CODES.has(code) ||
    (status !== undefined && status >= 500)
  ) {
    return "upstream_unavailable";
  }
  return "unknown";
};

// The JWK that the Okta Admin Console makes for a service app's key.
const rsaPrivateJwk = z.looseObject({
  kty: z.literal("RSA"),
  d: z.string().min(1),
  kid: z.string().min(1).optional(),
});

/** A service app's private key, and Okta's id for it if the JWK has one. */
export type PrivateKey = { key: KeyObject; kid?: string };

/**
 * Reads the service app's private key from the customer's own secret
 * manager, with the connector's own cloud identity. It is read on every call
 * and never kept, so a rotated key takes effect on the next one. The secret
 * holds the key as a JWK.
 *
 * Nothing of the key or of the secret's id goes into a log line or an error.
 */
export const readPrivateKey = async (
  pointer: SecretPointer,
  logger: Logger
): Promise<PrivateKey> => {
  const { manager, secretId } = pointer;
  const { config, managerName, locationLabel, readGrant } = vaultOf(pointer);
  const failed = (type: ConnectorErrorType, message: string) =>
    new ConnectorError({ message, payload: { manager }, type });

  const { value } = await createSecretManagerClient(config)
    .then((secrets) => secrets.getSecretValue({ ref: secretId as SecretRef }))
    .catch((error: unknown) => {
      // The secret manager's own errors quote the secret's id, so every
      // failure is described, not passed on.
      const facts = failureFacts(
        error instanceof SecretManagerError ? error.cause : error
      );
      logger.warn({ manager, ...facts }, "reading the private key failed");

      if (error instanceof SecretNotFoundError) {
        throw failed(
          "object_not_found",
          `The connector couldn't find the Okta service app's private key in ${managerName}. Check the secret's name and ${locationLabel} on the Okta app in P0, and that the secret exists and holds the key.`
        );
      }
      if (error instanceof UnauthorizedError) {
        throw failed(
          "insufficient_privileges",
          `The connector isn't allowed to read the Okta service app's private key in ${managerName}. Grant the connector's identity ${readGrant}. If it has that, check the secret's name and ${locationLabel} on the Okta app in P0: a secret that doesn't exist can be refused the same way.`
        );
      }
      const description = renderFailure(error);
      throw failed(
        typeOfUnmapped(facts),
        `The connector couldn't read the Okta service app's private key in ${managerName}${description === undefined ? "" : `: ${description}`}. Check the secret's ${locationLabel} on the Okta app in P0, and try again.`
      );
    });

  const notAKey = failed(
    "validation_error",
    `The secret in ${managerName} doesn't hold an RSA private key as a JWK. Store the private key that Okta made for the service app, in JWK format, as the secret's value.`
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(typeof value === "string" ? value : value.toString());
  } catch {
    throw notAKey;
  }
  const jwk = rsaPrivateJwk.safeParse(parsed);
  if (!jwk.success) throw notAKey;
  try {
    const key = createPrivateKey({ format: "jwk", key: jwk.data });
    return {
      key,
      ...(jwk.data.kid === undefined ? {} : { kid: jwk.data.kid }),
    };
  } catch {
    throw notAKey;
  }
};
