import {
  ConnectorError,
  type ConnectorErrorType,
  type Logger,
} from "@p0security/connector-core";
import {
  SecretAlreadyExistsError,
  type SecretManagerClient,
  type SecretRef as SecretManagerRef,
  SecretNotFoundError,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/secret-manager-client";

import type { SecretRef } from "./install/definition.ts";

const MANAGER_NAME = "Google Secret Manager";

/** The client for one project of the customer's Google Secret Manager. */
export const secretManagerFor = (projectId: string) =>
  createSecretManagerClient({ provider: "gcp", projectId });

/** Brands a bare secret name as the client's `SecretRef`. */
export const secretManagerRef = (secretId: string) =>
  secretId as SecretManagerRef;

// P0 can't change a site's or an agent account's fields after it creates
// them, so the customer fixes a wrong secret name or project by adding the
// record again.
const ADD_AGAIN =
  "If P0 has the wrong name or project for it, ask your P0 admin to delete the site (or agent account) in P0 and add it again.";

const failed = (type: ConnectorErrorType, message: string) =>
  new ConnectorError({ type, message, payload: { manager: "gcp" } });

/**
 * Turns a secret manager failure into a {@link ConnectorError}. `what` names
 * the secret for a person, such as "the Jira admin client secret".
 *
 * No message quotes the secret's id: Google's errors carry the request's URL,
 * which ends in it, so the error itself is not passed on either. The log
 * line keeps the error's name only.
 */
export const secretFailure = (
  error: unknown,
  what: string,
  grant: string,
  logger: Logger
): ConnectorError => {
  if (error instanceof ConnectorError) return error;
  logger.warn(
    { manager: "gcp", error: error instanceof Error ? error.name : "unknown" },
    `${what}: the secret manager call failed`
  );
  if (error instanceof SecretNotFoundError) {
    return failed(
      "object_not_found",
      `The connector couldn't find ${what}, or a value in it, in ${MANAGER_NAME}. Check that the secret exists there and has a value. ${ADD_AGAIN}`
    );
  }
  if (error instanceof UnauthorizedError) {
    return failed(
      "insufficient_privileges",
      `The connector isn't allowed to use ${what} in ${MANAGER_NAME}. Grant the connector's service account ${grant}. Google refuses a missing secret the same way, so also check that the secret exists. ${ADD_AGAIN}`
    );
  }
  return failed(
    "unknown",
    `The connector couldn't use ${what} in ${MANAGER_NAME}. Check the connector's Cloud Run logs for the error, then try again.`
  );
};

// The client throws a plain `Error` for a version with no payload, which is
// how Google returns an empty value. Its message is the only signal, so the
// match is on that exact prefix and a plain `Error` only.
const isEmptyPayload = (error: unknown) =>
  error instanceof Error &&
  error.constructor === Error &&
  error.message.startsWith(
    "GCP Secret Manager returned a version with no payload data"
  );

const emptySecret = (what: string) =>
  failed(
    "validation_error",
    `${capitalize(what)} in ${MANAGER_NAME} is empty. Add a new version of the secret whose whole value is ${what}.`
  );

const READ_GRANT =
  "roles/secretmanager.secretAccessor and roles/secretmanager.viewer on that secret";

/**
 * Settles as `work` does, or fails with `upstream_unavailable` at `deadline`
 * (epoch milliseconds), whichever comes first. The secret manager client
 * takes no abort signal, so a late answer is ignored rather than cancelled.
 */
const byDeadline = async <T>(
  work: Promise<T>,
  deadline: number,
  what: string
): Promise<T> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          failed(
            "upstream_unavailable",
            `${MANAGER_NAME} didn't return ${what} in time. Try the request again in a few minutes.`
          )
        ),
      Math.max(0, deadline - Date.now())
    );
  });
  try {
    return await Promise.race([work, late]);
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Reads a secret whose whole value is one string, such as an OAuth client
 * secret or an API key, on every call. The value goes back to the caller and
 * nowhere else. With a `deadline` (epoch milliseconds), the read fails with
 * `upstream_unavailable` when it hasn't finished by then.
 */
export const readSecretString = async (
  pointer: SecretRef,
  what: string,
  logger: Logger,
  deadline?: number
): Promise<string> => {
  const read = async (secrets: SecretManagerClient) =>
    await secrets.getSecretValue({ ref: secretManagerRef(pointer.secretId) });
  const reading = secretManagerFor(pointer.projectId)
    .then(read)
    .catch((error: unknown) => {
      throw isEmptyPayload(error)
        ? emptySecret(what)
        : secretFailure(error, what, READ_GRANT, logger);
    });
  const { value } = await (deadline === undefined
    ? reading
    : byDeadline(reading, deadline, what));
  const text = (
    typeof value === "string" ? value : value.toString("utf8")
  ).trim();
  if (text.length === 0) throw emptySecret(what);
  return text;
};

const capitalize = (text: string) =>
  text.charAt(0).toUpperCase() + text.slice(1);

const TOKEN_SECRET = "the request's token secret";

// The narrow set P0's installer grants: create on the project, and the rest
// only on secrets with the site's token prefix.
const VAULT_GRANT =
  "secretmanager.secrets.create on the vault project, and secretmanager.secrets.get, secretmanager.secrets.delete and secretmanager.versions.add on the site's token secrets";

/** Runs one call on the vault project's secret manager. */
const onVault = async <T>(
  projectId: string,
  logger: Logger,
  use: (secrets: SecretManagerClient) => Promise<T>
): Promise<T> => {
  try {
    return await use(await secretManagerFor(projectId));
  } catch (error) {
    throw secretFailure(error, TOKEN_SECRET, VAULT_GRANT, logger);
  }
};

/**
 * The token secret's bare name when it exists in the vault project, or
 * `null` when it doesn't.
 */
export const findTokenSecret = async (
  projectId: string,
  name: string,
  logger: Logger
): Promise<string | null> =>
  await onVault(projectId, logger, async (secrets) => {
    try {
      return (await secrets.getSecret({ ref: secretManagerRef(name) })).name;
    } catch (error) {
      if (error instanceof SecretNotFoundError) return null;
      throw error;
    }
  });

/**
 * Creates the token secret in the vault project, and returns its bare name.
 * A secret a retried call already created is reused.
 */
export const createTokenSecret = async (
  projectId: string,
  name: string,
  logger: Logger
): Promise<string> =>
  await onVault(projectId, logger, async (secrets) => {
    try {
      return (await secrets.createSecret({ name })).name;
    } catch (error) {
      if (error instanceof SecretAlreadyExistsError) return name;
      throw error;
    }
  });

/** Writes `value` to the token secret as its new version. */
export const writeTokenSecret = async (
  projectId: string,
  name: string,
  value: string,
  logger: Logger
) =>
  await onVault(projectId, logger, async (secrets) => {
    await secrets.createSecretVersion({
      ref: secretManagerRef(name),
      type: "value",
      value: Buffer.from(value),
    });
  });

/**
 * Deletes the token secret and every version of it. A secret that is
 * already gone counts as deleted, so a retried revoke succeeds.
 */
export const deleteTokenSecret = async (
  projectId: string,
  name: string,
  logger: Logger
) =>
  await onVault(projectId, logger, async (secrets) => {
    try {
      await secrets.deleteSecret({ ref: secretManagerRef(name) });
    } catch (error) {
      if (error instanceof SecretNotFoundError) return;
      throw error;
    }
  });
