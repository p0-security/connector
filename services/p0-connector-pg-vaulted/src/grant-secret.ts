import {
  SecretAlreadyExistsError,
  type SecretManagerClient,
  SecretNotFoundError,
  type SecretRef,
} from "@p0security/connector-secret-manager-client";
import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";

import type { PgRequestContext } from "./accesses/common/definition.ts";
import { ident } from "./sql/identifier.ts";

/** PostgreSQL's own default for `scram_iterations`. */
const SCRAM_ITERATIONS = 4096;

/** 256 random bits, as base64url, which needs no SASLprep. */
export const generateGrantPassword = (): string =>
  randomBytes(32).toString("base64url");

/**
 * Renders the SCRAM-SHA-256 verifier PostgreSQL stores for `password`. The
 * connector sends this in place of the password, so the password never
 * reaches the server's statement log.
 */
export const renderScramVerifier = (
  password: string,
  salt: Buffer = randomBytes(16)
): string => {
  const salted = pbkdf2Sync(password, salt, SCRAM_ITERATIONS, 32, "sha256");
  const clientKey = createHmac("sha256", salted).update("Client Key").digest();
  const storedKey = createHash("sha256").update(clientKey).digest();
  const serverKey = createHmac("sha256", salted).update("Server Key").digest();
  return `SCRAM-SHA-256$${SCRAM_ITERATIONS}:${salt.toString("base64")}$${storedKey.toString("base64")}:${serverKey.toString("base64")}`;
};

/**
 * The secret is named after the login, so one secret can never hold another
 * login's password. `ident` refuses a `/`, so the name stays in the prefix.
 */
export const grantSecretRef = (
  context: PgRequestContext,
  username: string
): SecretRef => {
  ident(username);
  return `${context.grantSecretPrefix}/${username}` as SecretRef;
};

export const hasGrantSecret = async (
  secrets: SecretManagerClient,
  ref: SecretRef
): Promise<boolean> => {
  try {
    await secrets.getSecret({ ref });
    return true;
  } catch (error) {
    if (error instanceof SecretNotFoundError) return false;
    throw error;
  }
};

/**
 * Secrets Manager deletes a secret a few seconds after `deleteSecret`
 * returns, and until then refuses to create or write one by that name. A
 * grant that follows the last revoke closely waits that out.
 */
const PENDING_DELETION_DELAYS_MS = [1000, 2000, 4000, 8000];

const isPendingDeletion = (error: unknown): boolean =>
  error instanceof Error &&
  error.name === "InvalidRequestException" &&
  /deletion/i.test(error.message);

/**
 * A secret left from an earlier login is reused: that login is gone, so
 * its password no longer signs in to anything.
 */
export const writeGrantSecret = async (
  secrets: SecretManagerClient,
  ref: SecretRef,
  password: string,
  delaysMs: readonly number[] = PENDING_DELETION_DELAYS_MS
): Promise<void> => {
  for (let attempt = 0; ; attempt++) {
    try {
      await secrets.createSecret({ name: ref }).catch((error: unknown) => {
        if (!(error instanceof SecretAlreadyExistsError)) throw error;
      });
      await secrets.createSecretVersion({
        ref,
        type: "value",
        value: Buffer.from(password),
      });
      return;
    } catch (error) {
      const delayMs = delaysMs[attempt];
      if (delayMs === undefined || !isPendingDeletion(error)) throw error;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
};

export const deleteGrantSecret = async (
  secrets: SecretManagerClient,
  ref: SecretRef
): Promise<void> => {
  await secrets.deleteSecret({ ref }).catch((error: unknown) => {
    if (!(error instanceof SecretNotFoundError)) throw error;
  });
};
