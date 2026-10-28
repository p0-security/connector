import { ConnectorError } from "@p0security/connector";
import {
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/secret-manager-client";

import type { PrivateKeyPointer } from "./accesses/role/definition.ts";

// What the connector's identity needs on the one secret.
const READ_GRANT =
  "secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key";

/**
 * Reads the customer app's private key from the customer's vault.
 *
 * The connector's own cloud identity does the read, and is granted access to
 * exactly this one secret. The key is returned to the caller and goes nowhere
 * else: not into a log line and not into an error.
 */
export const getGithubPrivateKey = async (
  pointer: PrivateKeyPointer
): Promise<string> => {
  const { secretId, region } = pointer;
  const secrets = await createSecretManagerClient({ provider: "aws", region });
  try {
    const { value } = await secrets.getSecretValue({
      ref: secretId as SecretRef,
    });
    // Normalize keys stored with escaped "\n" (a common way PEM keys get saved as
    // a single-line secret) back to real newlines; a genuine multi-line PEM is
    // unaffected since its newlines are real 0x0A bytes, not the two-char "\n".
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
        message: `The connector isn't allowed to read the GitHub App private key secret ${secretId}. Grant the connector's identity ${READ_GRANT}.`,
        payload: { secretId, manager: pointer.manager },
      });
    }
    throw error;
  }
};
