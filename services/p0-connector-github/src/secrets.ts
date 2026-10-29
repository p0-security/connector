import { ConnectorError, throwAssertNever } from "@p0security/connector-core";
import {
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";

import type { PrivateKeyPointer } from "./accesses/common/definition.ts";

const secretManagerConfig = (
  pointer: PrivateKeyPointer
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

// What the connector's identity needs on the one secret. GCP's client reads the
// value with `versions.access` and then its metadata with `versions.get`, so
// the usual Secret Accessor role alone isn't enough.
const READ_GRANT: Record<PrivateKeyPointer["manager"], string> = {
  aws: "secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key",
  gcp: "secretmanager.versions.access and secretmanager.versions.get on that secret",
};

/**
 * Reads the customer app's private key from the customer's vault.
 *
 * The connector's own cloud identity does the read, and is granted access to
 * exactly this one secret. The key is returned to the caller and goes nowhere
 * else: not into a log line and not into an error.
 */
export const fetchGitHubPrivateKey = async (
  pointer: PrivateKeyPointer
): Promise<string> => {
  const { secretId } = pointer;
  const secrets = await createSecretManagerClient(secretManagerConfig(pointer));
  try {
    const { value } = await secrets.getSecretValue({
      ref: secretId as SecretRef,
    });
    // A key stored with escaped "\n" (a common way to save a PEM key as a
    // single-line secret) gets its real newlines back. A genuine multi-line PEM
    // is unaffected, since its newlines are real 0x0A bytes, not the two-char
    // "\n".
    const rawKey = typeof value === "string" ? value : value.toString("utf8");
    return rawKey.replace(/\\n/g, "\n");
  } catch (error) {
    if (error instanceof SecretNotFoundError) {
      throw new ConnectorError({
        type: "object_not_found",
        message: `The connector couldn't find the GitHub App private key secret ${secretId}. Check the private key secret in the P0 install, and that the secret still exists.`,
        payload: { query: secretId, manager: pointer.manager },
      });
    }
    if (error instanceof UnauthorizedError) {
      throw new ConnectorError({
        type: "insufficient_privileges",
        message: `The connector isn't allowed to read the GitHub App private key secret ${secretId}. Grant the connector's identity ${READ_GRANT[pointer.manager]}.`,
        payload: { secretId, manager: pointer.manager },
      });
    }
    throw error;
  }
};
