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
  type SecretPayload,
  type SecretRef,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/secret-manager-client";

import type { SecretPointer } from "./accesses/project-role/definition.ts";
import {
  ADMIN_SECRET_SHAPE,
  type AdminCredential,
  parseAdminCredential,
} from "./admin-credential.ts";
import { type FailureFacts, describeFailure, failureFacts } from "./failure.ts";

type Vault = {
  config: SecretManagerProviderConfig;
  /** The secret manager's name, for a message. */
  managerName: string;
  /** What, beside its name, places a secret in this secret manager. */
  locationLabel: string;
  /** What the connector's identity needs on the secret. */
  readGrant: string;
};

const vaultOf = (pointer: SecretPointer): Vault => {
  switch (pointer.manager) {
    case "aws":
      return {
        config: { provider: "aws", region: pointer.region },
        managerName: "AWS Secrets Manager",
        locationLabel: "region",
        readGrant:
          "secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key",
      };
    case "gcp":
      return {
        config: { provider: "gcp", projectId: pointer.projectId },
        managerName: "Google Secret Manager",
        locationLabel: "project",
        // The shared client reads the version's payload and then its
        // metadata, and the accessor role doesn't cover the second read.
        readGrant:
          "roles/secretmanager.secretAccessor and roles/secretmanager.viewer on that secret",
      };
    default:
      throw throwAssertNever(pointer);
  }
};

// Failures to reach the secret manager at all, by Node's code for them.
const NETWORK_FAILURES: ReadonlySet<unknown> = new Set([
  "ENOTFOUND",
  "EAI_AGAIN",
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
]);

/**
 * The type of a failure the secret manager client gave no error of its own:
 * throttling and outages by what they are, so P0 can tell a call worth
 * trying again from one that isn't, and `unknown` for the rest.
 */
const typeOfUnmapped = ({
  name,
  code,
  status,
}: FailureFacts): ConnectorErrorType => {
  if (name === "ThrottlingException" || status === 429) return "rate_limited";
  if (NETWORK_FAILURES.has(code) || (status !== undefined && status >= 500)) {
    return "upstream_unavailable";
  }
  return "unknown";
};

/** The secret's value as JSON, or `undefined` when it isn't JSON. */
const parseJson = (value: SecretPayload): unknown => {
  try {
    // AWS returns a text secret as a string. Google returns bytes.
    return JSON.parse(
      typeof value === "string" ? value : value.toString("utf8")
    );
  } catch {
    return undefined;
  }
};

/**
 * Reads a secret from the customer's own secret manager, with the connector's
 * own cloud identity, and returns its value as JSON, or `undefined` when it
 * isn't JSON. It is read on every call and never kept, so a rotated secret
 * takes effect on the next one.
 *
 * The value goes back to the caller and nowhere else: not into a log line
 * and not into an error. Nothing of the pointer but its manager goes into
 * either. The secret's id least of all: on AWS it is any string, so a
 * credential pasted where the name goes would travel with the message.
 */
const readSecretJson = async (
  pointer: SecretPointer,
  logger: Logger
): Promise<{ json: unknown; vault: Vault }> => {
  const { manager, secretId } = pointer;
  const vault = vaultOf(pointer);
  const { config, managerName, locationLabel, readGrant } = vault;
  const failed = (type: ConnectorErrorType, message: string) =>
    new ConnectorError({ type, message, payload: { manager } });

  const { value } = await createSecretManagerClient(config)
    .then((secrets) =>
      // `SecretRef` brands the secret manager's own name for a secret, which
      // is what the customer gave P0.
      secrets.getSecretValue({ ref: secretId as SecretRef })
    )
    .catch((error: unknown) => {
      // Every failure is described, not passed on. The secret manager's own
      // errors quote the id they were given, and Google's carry the
      // request's URL, which ends in it. The client wraps the vendor's error
      // in the two it maps, so that is where their facts are.
      const facts = failureFacts(
        error instanceof SecretManagerError ? error.cause : error
      );
      // What P0 gets is a sentence. This line is what's left for whoever has
      // to find out why.
      logger.warn(
        { manager, ...facts },
        "reading the admin credential's secret failed"
      );

      if (error instanceof SecretNotFoundError) {
        throw failed(
          "object_not_found",
          `The connector couldn't find its Harbor admin credential's secret, or a value in it, in ${managerName}. Check the secret's name and ${locationLabel} on the Harbor instance in P0, and that the secret exists and holds the admin credential's JSON.`
        );
      }
      if (error instanceof UnauthorizedError) {
        throw failed(
          "insufficient_privileges",
          `The connector isn't allowed to read its Harbor admin credential's secret in ${managerName}. Grant the connector's identity ${readGrant}. If it has that, check the secret's name and ${locationLabel} on the Harbor instance in P0: a secret that doesn't exist can be refused the same way.`
        );
      }
      const description = describeFailure(error);
      throw failed(
        typeOfUnmapped(facts),
        `The connector couldn't read its Harbor admin credential's secret in ${managerName}${description === undefined ? "" : `: ${description}`}. Check the secret's ${locationLabel} on the Harbor instance in P0, and try again.`
      );
    });
  return { json: parseJson(value), vault };
};

/**
 * Reads the Harbor admin credential from the customer's own secret manager
 * ({@link readSecretJson}), on every call, and parses it strictly
 * ({@link parseAdminCredential}).
 */
export const readAdminCredential = async (
  pointer: SecretPointer,
  logger: Logger
): Promise<AdminCredential> => {
  const { manager } = pointer;
  const {
    json,
    vault: { managerName },
  } = await readSecretJson(pointer, logger);
  const parsed = parseAdminCredential(json);
  if (!parsed.ok) {
    throw new ConnectorError({
      type: "validation_error",
      message: `The secret for the Harbor admin credential in ${managerName} isn't the JSON the connector expects${parsed.problem}. Store ${ADMIN_SECRET_SHAPE} as its value.`,
      payload: { manager },
    });
  }
  return parsed.credential;
};
