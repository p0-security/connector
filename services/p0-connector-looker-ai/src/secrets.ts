import { ConnectorError } from "@p0security/connector";
import {
  SecretAlreadyExistsError,
  type SecretManagerClient,
  SecretNotFoundError,
  type SecretPayload,
  type SecretRef,
  UnauthorizedError,
} from "@p0security/secret-manager-client";
import { z } from "zod";

import type { LookerApiKey } from "./looker/looker-api.ts";

const apiKey = z.object({
  client_id: z.string().min(1),
  client_secret: z.string().min(1),
});

// The secret manager takes a secret's id wherever it takes a ref.
const toSecretRef = (secretId: string) => secretId as SecretRef;

/** Parses a secret value as JSON. Returns `undefined` when it is not JSON. */
const parseJsonPayload = (value: SecretPayload): unknown => {
  try {
    return JSON.parse(
      typeof value === "string" ? value : value.toString("utf8")
    );
  } catch {
    return undefined;
  }
};

/** Reads the Looker Admin API key that P0 uses to create and delete each
 * grant's Looker service account. */
export const fetchAdminKey = async (
  secrets: SecretManagerClient,
  secretId: string
): Promise<LookerApiKey> => {
  const { value } = await secrets
    .getSecretValue({ ref: toSecretRef(secretId) })
    .catch((error: unknown) => {
      if (error instanceof SecretNotFoundError) {
        throw new ConnectorError({
          type: "object_not_found",
          message: `The connector couldn't find the Looker Admin API key secret ${secretId}. Check the Admin key secret in the P0 install, and that the secret has a version.`,
          payload: { query: secretId },
        });
      }
      if (error instanceof UnauthorizedError) {
        throw new ConnectorError({
          type: "insufficient_privileges",
          message: `The connector isn't allowed to read the Looker Admin API key secret ${secretId}. Grant the connector's GCP service account roles/secretmanager.secretAccessor and roles/secretmanager.viewer on that secret.`,
          payload: { secretId },
        });
      }
      throw error;
    });
  const parsed = apiKey.safeParse(parseJsonPayload(value));
  if (!parsed.success) {
    // Neither log nor return the value: it holds the Admin key.
    throw new ConnectorError({
      type: "validation_error",
      message:
        'The Looker Admin API key secret must be JSON of the form {"client_id": "...", "client_secret": "..."}',
      payload: {},
    });
  }
  return parsed.data;
};

/**
 * The error for a grant secret that could not be written.
 *
 * The failed request holds the key, and the secret manager's own error can
 * carry that request, which the framework would log. So this replaces that
 * error, and never passes it on as a cause.
 */
const newGrantSecretWriteError = (name: string, error: unknown) =>
  error instanceof UnauthorizedError
    ? new ConnectorError({
        type: "insufficient_privileges",
        message: `The connector isn't allowed to write the grant's secret ${name}. Check that the connector's GCP service account can create secrets, and add versions to the secrets that P0 names.`,
        payload: { secretId: name },
      })
    : new ConnectorError({
        type: "upstream_unavailable",
        message: `The connector couldn't write the grant's secret ${name}: ${
          error instanceof Error ? error.message : String(error)
        }`,
        payload: { secretId: name },
      });

/**
 * What a key field may hold. The secret is the client ID and the client secret
 * with a `:` between them, and the MCP server spec splits it there, so a field
 * may not hold a `:`. The Toolbox also pastes each field into its YAML config,
 * so anything but letters and digits is refused. Nothing documents what Looker
 * puts in a key (W4).
 */
const KEY_FIELD = /^[A-Za-z0-9]+$/;

/** The character between the client ID and the client secret. */
const GRANT_SECRET_SEPARATOR = ":";

/**
 * Writes a grant's Looker API key to the grant's secret, as
 * `<client_id>:<client_secret>`, and creates the secret when there is none.
 *
 * Refuses a key with any character but a letter or a digit, before it creates
 * the secret, so that splitting the secret at the `:` always gives back the
 * two fields.
 */
export const setGrantSecret = async (
  secrets: SecretManagerClient,
  name: string,
  key: LookerApiKey
) => {
  if (!KEY_FIELD.test(key.client_id) || !KEY_FIELD.test(key.client_secret)) {
    // Quote none of the key, not even part of it.
    throw new ConnectorError({
      type: "unknown",
      message:
        "Looker returned an API key whose client ID or client secret holds a character other than a letter or a digit, which the MCP server can't use. The connector didn't store it.",
      payload: { secretId: name },
    });
  }
  try {
    await secrets.createSecret({ name });
  } catch (error) {
    // An earlier attempt at this grant created the secret and failed later.
    if (!(error instanceof SecretAlreadyExistsError)) {
      throw newGrantSecretWriteError(name, error);
    }
  }
  try {
    await secrets.createSecretVersion({
      ref: toSecretRef(name),
      type: "value",
      value: Buffer.from(
        `${key.client_id}${GRANT_SECRET_SEPARATOR}${key.client_secret}`
      ),
    });
  } catch (error) {
    throw newGrantSecretWriteError(name, error);
  }
};

/** Deletes a grant's secret. A secret that does not exist is not an error. */
export const deleteGrantSecret = async (
  secrets: SecretManagerClient,
  name: string
) => {
  try {
    await secrets.deleteSecret({ ref: toSecretRef(name) });
  } catch (error) {
    if (!(error instanceof SecretNotFoundError)) throw error;
  }
};
