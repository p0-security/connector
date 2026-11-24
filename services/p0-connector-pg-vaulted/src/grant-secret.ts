import {
  DescribeSecretCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import { ConnectorError } from "@p0security/connector-core";
import {
  SecretAlreadyExistsError,
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";

import type { ConnectSecretManager, Dependencies } from "./dependencies.ts";

/** The store's part of the shared client, which leaves out the read: the
 * connector never reads a grant secret's value. */
type GrantSecretWriter = Pick<
  Awaited<ReturnType<ConnectSecretManager>>,
  "createSecret" | "createSecretVersion" | "deleteSecret"
>;

// Secrets Manager takes a secret's name where it takes its ARN. The shared
// client's refs are a brand on a string, which only a cast makes.
const refOf = (name: string) => name as SecretRef;

const isNamed = (error: unknown, name: string): error is Error =>
  error instanceof Error && error.name === name;

// copy of `REFUSAL_NAMES` in services/p0-connector-aws-ssm-ai/src/secrets.ts,
// for the one call the store makes with the SDK itself
const REFUSAL_NAMES = [
  "AccessDeniedException",
  "UnrecognizedClientException",
  "InvalidClientTokenId",
  "NotAuthorized",
];

const isRefusal = (error: unknown) =>
  error instanceof UnauthorizedError ||
  REFUSAL_NAMES.some((name) => isNamed(error, name));

// copy of `isStillDeleting` in services/p0-connector-aws-ssm-ai/src/secrets.ts
/**
 * Secrets Manager deletes a secret in the background, and refuses a new one
 * with the same name until the deletion finishes.
 */
const isStillDeleting = (error: unknown) =>
  isNamed(error, "InvalidRequestException") &&
  /scheduled for deletion/i.test(error.message);

/** Each of the store's calls: how an error names it, and the IAM actions it
 * takes. */
const CALLS = {
  describe: { words: "look up", actions: "secretsmanager:DescribeSecret" },
  create: {
    words: "create",
    actions: "secretsmanager:CreateSecret and secretsmanager:DescribeSecret",
  },
  write: { words: "write", actions: "secretsmanager:PutSecretValue" },
  remove: { words: "delete", actions: "secretsmanager:DeleteSecret" },
};

/**
 * A Secrets Manager failure, without its cause or its message. The request
 * of a write holds the grant login's password, and the connector does not
 * vouch for what an SDK error carries, so neither is passed on or logged.
 */
const toGrantSecretError = (call: keyof typeof CALLS, error: unknown) => {
  if (error instanceof ConnectorError) return error;
  const { words, actions } = CALLS[call];
  if (isRefusal(error)) {
    return new ConnectorError({
      type: "insufficient_privileges",
      message: `Secrets Manager refused to let the connector ${words} the grant secret. Give the connector's role ${actions} on the secrets under p0/secrets/postgres/<vpc id>/.`,
      payload: {},
    });
  }
  if (isStillDeleting(error)) {
    return new ConnectorError({
      type: "upstream_unavailable",
      message:
        "Secrets Manager is still deleting an earlier grant secret with this name. Try again in a moment.",
      payload: {},
    });
  }
  return new ConnectorError({
    type: "upstream_unavailable",
    message: `The connector could not ${words} the grant secret.`,
    payload: {},
  });
};

export type GrantSecretStore = {
  /**
   * The named grant secret, or `null` when there is none or AWS is deleting
   * it. `hasValue` is false for a secret that was created and never
   * written.
   */
  describe: (name: string) => Promise<{ hasValue: boolean } | null>;
  /** Creates the named grant secret with no value, or finds it. */
  findOrCreate: (name: string) => Promise<void>;
  /** Makes `value` the named grant secret's current value. */
  write: (name: string, value: string) => Promise<void>;
  /** Deletes the named grant secret with its value, at once. A secret that
   * is already gone is deleted. */
  remove: (name: string) => Promise<void>;
};

// modelled on `newSecretStore` in services/p0-connector-aws-ssm-ai/src/secrets.ts
/**
 * The grant secrets: AWS Secrets Manager in `region`, as the connector's own
 * execution role. It creates, describes, writes and deletes a secret, and
 * has no way to read one.
 */
export const newGrantSecretStore = (
  region: string,
  dependencies: Dependencies
): GrantSecretStore => {
  const {
    connectSecretManager = createSecretManagerClient,
    secretsManagerSdk = (sdkRegion) =>
      new SecretsManagerClient({ region: sdkRegion }),
  } = dependencies;
  const writer = (): Promise<GrantSecretWriter> =>
    connectSecretManager({ provider: "aws", region });

  const at = async <T>(call: keyof typeof CALLS, run: () => Promise<T>) => {
    try {
      return await run();
    } catch (error) {
      throw toGrantSecretError(call, error);
    }
  };

  return {
    // The shared client's `getSecret` drops `DeletedDate` and the versions,
    // so the store asks the SDK.
    describe: (name) =>
      at("describe", async () => {
        try {
          const { DeletedDate, VersionIdsToStages = {} } =
            await secretsManagerSdk(region).send(
              new DescribeSecretCommand({ SecretId: name })
            );
          // A secret AWS is still deleting counts as gone, so a grant goes
          // on to create one. That fails until the deletion finishes, as a
          // short outage that a later try gets past.
          if (DeletedDate) return null;
          return {
            // A version with a staging label is one the secret serves.
            hasValue: Object.values(VersionIdsToStages).some(
              (stages) => stages.length > 0
            ),
          };
        } catch (error) {
          if (isNamed(error, "ResourceNotFoundException")) return null;
          throw error;
        }
      }),
    findOrCreate: (name) =>
      at("create", async () => {
        const secrets = await writer();
        try {
          await secrets.createSecret({ name });
        } catch (error) {
          // An earlier try stopped after it created the secret.
          if (!(error instanceof SecretAlreadyExistsError)) throw error;
        }
      }),
    write: (name, value) =>
      at("write", async () => {
        const secrets = await writer();
        await secrets.createSecretVersion({
          ref: refOf(name),
          type: "value",
          value: Buffer.from(value),
        });
      }),
    remove: (name) =>
      at("remove", async () => {
        const secrets = await writer();
        try {
          await secrets.deleteSecret({ ref: refOf(name) });
        } catch (error) {
          // An earlier try stopped after it deleted the secret.
          if (!(error instanceof SecretNotFoundError)) throw error;
        }
      }),
  };
};
