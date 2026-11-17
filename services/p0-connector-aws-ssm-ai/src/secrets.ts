import {
  DescribeSecretCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import { ConnectorError } from "@p0security/connector-core";
import {
  SecretAlreadyExistsError,
  type SecretManagerClient,
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";

import type { SecretStep } from "./failures.ts";
import { isNamed, nameOf } from "./ssm/errors.ts";

/** Opens the shared secret manager client. */
export type ConnectSecretManager = (
  config: SecretManagerProviderConfig
) => Promise<SecretManagerClient>;

/** What stands in for AWS in tests. */
export type SecretStoreDependencies = {
  connect?: ConnectSecretManager;
  /** The SDK client that describes a secret. */
  client?: Pick<SecretsManagerClient, "send">;
};

/** The request a store serves. */
export type SecretStoreScope = { region: string; requestId: string };

// The shared client's refs are a brand on a string, which only a cast makes.
const refOf = (nameOrArn: string) => nameOrArn as SecretRef;

const messageOf = (error: unknown) =>
  error instanceof Error ? error.message : undefined;

// copied from packages/secret-manager-client/src/providers/aws.ts
// (`unauthorizedMappings`), for the one call the store makes with the SDK
// itself
const REFUSAL_NAMES = [
  "AccessDeniedException",
  "UnrecognizedClientException",
  "InvalidClientTokenId",
  "NotAuthorized",
];

const isRefusal = (error: unknown): error is Error =>
  error instanceof UnauthorizedError ||
  REFUSAL_NAMES.some((name) => isNamed(error, name));

/**
 * AWS's own words for a refusal: the action the role may not take and the
 * secret it may not take it on. A refusal never quotes a secret's value.
 */
const refusalOf = (error: unknown) => {
  const reason = messageOf(
    error instanceof UnauthorizedError ? error.cause : error
  );
  return reason ? `: ${reason.replace(/\.$/, "")}` : "";
};

/** Each step as the end of "the connector tried to ...". */
const STEP_WORDS: Record<SecretStep, string> = {
  describe_secret: "look up the secret",
  create_secret: "create the secret",
  write_secret: "write the secret",
  delete_secret: "delete the secret",
};

/**
 * Secrets Manager deletes a secret in the background, and refuses a new one
 * with the same name until the deletion finishes. A grant that follows a
 * revoke of the same group can meet that, and passes when P0 tries it again.
 */
const isStillDeleting = (error: unknown): error is Error =>
  isNamed(error, "InvalidRequestException") &&
  /scheduled for deletion/i.test(error.message);

/**
 * Maps a Secrets Manager failure to the error P0 shows. For a refusal it
 * keeps AWS's message. For anything else it keeps the failure's name and
 * nothing more: an SDK message can quote its request, and the request that
 * writes the secret holds the private key.
 *
 * A throttle is `rate_limited`. Every other failure, such as Secrets
 * Manager's own `InternalServiceError` or a network timeout, counts as
 * Secrets Manager being unavailable, as it does for SSM, not as P0's bug.
 */
const toSecretError = (step: SecretStep, requestId: string, error: unknown) => {
  if (error instanceof ConnectorError) return error;
  const name = nameOf(error);
  const payload = { step, requestId, ...(name ? { awsError: name } : {}) };
  const words = STEP_WORDS[step];
  if (isRefusal(error)) {
    return new ConnectorError({
      type: "insufficient_privileges",
      message: `Secrets Manager refused to let the connector's role ${words}${refusalOf(error)}. Give the connector's role this action on the secret.`,
      payload,
    });
  }
  return new ConnectorError({
    type:
      name === "ThrottlingException" ? "rate_limited" : "upstream_unavailable",
    message: `Secrets Manager failed when the connector tried to ${words} (${name ?? "unknown error"}). Try again, and contact P0 support if it keeps failing.`,
    payload,
  });
};

export type SecretState = {
  arn: string;
  /** False for a secret that a grant created and never wrote. */
  hasValue: boolean;
};

export type SecretStore = {
  /**
   * The named secret, or `null` when there is none or AWS is deleting it.
   * Never reads a value.
   */
  describe: (name: string) => Promise<SecretState | null>;
  /** Creates the named secret with no value, or finds it. Returns its ARN. */
  findOrCreate: (name: string) => Promise<string>;
  /** Makes `value` the secret's current value. */
  write: (arn: string, value: string) => Promise<void>;
  /** Deletes the secret. One that is already gone counts as deleted. */
  remove: (arn: string) => Promise<void>;
};

/**
 * The agent's key store: AWS Secrets Manager in the region the request
 * names, as the connector's own execution role. Every error it throws names
 * the request.
 */
export const newSecretStore = (
  scope: SecretStoreScope,
  dependencies: SecretStoreDependencies = {}
): SecretStore => {
  const { region, requestId } = scope;
  const { connect = createSecretManagerClient } = dependencies;
  const client = () => connect({ provider: "aws", region });

  const at = async <T>(step: SecretStep, run: () => Promise<T>) => {
    try {
      return await run();
    } catch (error) {
      throw toSecretError(step, requestId, error);
    }
  };

  // The shared client's `getSecret` drops `DeletedDate`, so the store asks
  // the SDK, with the region and credentials the shared client uses.
  const describe = (name: string) =>
    at("describe_secret", async () => {
      const sdk = dependencies.client ?? new SecretsManagerClient({ region });
      try {
        const described = await sdk.send(
          new DescribeSecretCommand({ SecretId: name })
        );
        const { ARN, DeletedDate, VersionIdsToStages = {} } = described;
        // A secret AWS is still deleting counts as gone, so a grant goes on
        // to create one. That fails until the deletion finishes, as a short
        // outage that a later try gets past.
        if (DeletedDate) return null;
        if (!ARN) throw new Error("DescribeSecret returned no ARN");
        return {
          arn: ARN,
          // A version with a staging label is one the secret serves, as the
          // shared client counts it.
          hasValue: Object.values(VersionIdsToStages).some(
            (stages) => stages.length > 0
          ),
        };
      } catch (error) {
        if (isNamed(error, "ResourceNotFoundException")) return null;
        throw error;
      }
    });

  return {
    describe,
    findOrCreate: (name) =>
      at("create_secret", async () => {
        const secrets = await client();
        try {
          return (await secrets.createSecret({ name })).ref;
        } catch (error) {
          if (isStillDeleting(error)) {
            throw new ConnectorError({
              // P0 tells the requester to try again in a few minutes, and
              // records no bug of its own.
              type: "upstream_unavailable",
              message:
                "Secrets Manager is still deleting the previous secret with this name. Try again in a moment.",
              payload: {
                step: "create_secret",
                requestId,
                awsError: error.name,
              },
            });
          }
          if (!(error instanceof SecretAlreadyExistsError)) throw error;
          // An earlier grant stopped after it created the secret.
          const existing = await describe(name);
          if (!existing) throw error;
          return existing.arn;
        }
      }),
    write: (arn, value) =>
      at("write_secret", async () => {
        const secrets = await client();
        await secrets.createSecretVersion({
          ref: refOf(arn),
          type: "value",
          value: Buffer.from(value),
        });
      }),
    remove: (arn) =>
      at("delete_secret", async () => {
        const secrets = await client();
        try {
          await secrets.deleteSecret({ ref: refOf(arn) });
        } catch (error) {
          if (!(error instanceof SecretNotFoundError)) throw error;
        }
      }),
  };
};
