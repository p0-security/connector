import {
  CreateSecretCommand,
  DeleteSecretCommand,
  DescribeSecretCommand,
  GetSecretValueCommand,
  ListSecretVersionIdsCommand,
  ListSecretsCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
  UpdateSecretVersionStageCommand,
} from "@aws-sdk/client-secrets-manager";
import type {
  SecretListEntry,
  SecretVersionsListEntry,
} from "@aws-sdk/client-secrets-manager";
import { randomBytes } from "node:crypto";

import {
  SecretAlreadyExistsError,
  SecretNotFoundError,
  SecretVersionNotFoundError,
  UnauthorizedError,
} from "../errors.ts";
import { listAllPages } from "../pagination.ts";
import type {
  SecretManagerClient,
  SecretManagerProviderConfig,
  SecretMetadata,
  SecretRef,
  SecretValue,
  SecretVersionRef,
  SecretVersionState,
  VersionMetadata,
} from "../types.ts";

type AwsSecretManagerConfig = Extract<
  SecretManagerProviderConfig,
  { provider: "aws" }
>;

/** Extracts the AWS SDK exception name from a rejected command, if present. */
const getErrorName = (error: unknown): string | undefined => {
  if (typeof error !== "object" || error === null) return undefined;
  const name = (error as { name?: unknown }).name;
  return typeof name === "string" ? name : undefined;
};

type ErrorMapping = { name: string; toError: (error: unknown) => Error };

/** Standard access-denied -> UnauthorizedError mappings shared by all AWS calls. */
const unauthorizedMappings = (): ErrorMapping[] => [
  {
    name: "AccessDeniedException",
    toError: (error) => new UnauthorizedError("aws", { cause: error }),
  },
  {
    name: "UnrecognizedClientException",
    toError: (error) => new UnauthorizedError("aws", { cause: error }),
  },
  {
    name: "InvalidClientTokenId",
    toError: (error) => new UnauthorizedError("aws", { cause: error }),
  },
  {
    name: "NotAuthorized",
    toError: (error) => new UnauthorizedError("aws", { cause: error }),
  },
];

/** Runs `fn`, rethrowing as a mapped error type if its AWS exception name matches one of `mappings`. */
const withErrorMapping = async <T>(
  fn: () => Promise<T>,
  mappings: ErrorMapping[]
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    const mapping = mappings.find((m) => m.name === getErrorName(error));
    throw mapping ? mapping.toError(error) : error;
  }
};

/** Base delay (ms) and multiplicative factor for `withRetry`'s exponential backoff. */
const RETRY_BACKOFF_BASE_MS = 100;
const RETRY_BACKOFF_FACTOR = 2;

/**
 * Retries `fn` with bounded exponential backoff while `isRetryable(error)` holds,
 * up to `attempts` total tries. Used to ride out AWS's brief propagation delay
 * (e.g. a DescribeSecret right after a CreateSecret can 404 for a moment).
 */
const withRetry = async <T>(
  fn: () => Promise<T>,
  {
    attempts,
    isRetryable,
  }: { attempts: number; isRetryable: (error: unknown) => boolean }
): Promise<T> => {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (attempt >= attempts || !isRetryable(error)) throw error;
      await new Promise((resolve) =>
        setTimeout(
          resolve,
          RETRY_BACKOFF_FACTOR ** attempt * RETRY_BACKOFF_BASE_MS
        )
      );
    }
  }
};

/** Converts an AWS secret resource into the client's SecretMetadata shape. */
const toSecretMetadata = (secret: {
  ARN?: string;
  Name?: string;
  CreatedDate?: Date;
}): SecretMetadata => {
  if (!secret.ARN || !secret.Name) {
    throw new Error("AWS Secrets Manager returned a secret with no ARN/Name");
  }
  return {
    ref: secret.ARN as SecretRef,
    name: secret.Name,
    createTime: secret.CreatedDate ?? new Date(0),
  };
};

/**
 * AWS has no per-version resource identifier of its own (only a bare VersionId,
 * scoped to its parent secret), so SecretVersionRef is a composite of the two
 */
const VERSION_REF_SEPARATOR = "/versions/";

const toVersionRef = (secretRef: SecretRef, versionId: string) =>
  `${secretRef}${VERSION_REF_SEPARATOR}${versionId}` as SecretVersionRef;

const parseVersionRef = (
  ref: SecretVersionRef
): { secretRef: SecretRef; versionId: string } => {
  const index = ref.lastIndexOf(VERSION_REF_SEPARATOR);
  if (index === -1) {
    throw new Error(`Malformed AWS secret version ref: "${ref}"`);
  }
  return {
    secretRef: ref.slice(0, index) as SecretRef,
    versionId: ref.slice(index + VERSION_REF_SEPARATOR.length),
  };
};

/**
 * Maps AWS staging labels onto the client's SecretVersionState. AWS has no
 * "destroyed" state: a version with no staging labels is merely "deprecated"
 * and is purged by Secrets Manager on its own, unobservable schedule.
 */
const toVersionState = (stages?: string[]): SecretVersionState =>
  stages && stages.length > 0 ? "enabled" : "disabled";

/** Converts an AWS secret version entry into the client's VersionMetadata shape. */
const toVersionMetadata = (
  version: SecretVersionsListEntry,
  secretRef: SecretRef
): VersionMetadata => {
  if (!version.VersionId) {
    throw new Error("AWS Secrets Manager returned a version with no VersionId");
  }
  return {
    ref: toVersionRef(secretRef, version.VersionId),
    secretRef,
    state: toVersionState(version.VersionStages),
    createTime: version.CreatedDate ?? new Date(0),
  };
};

/** Number of attempts allowed when retrying DescribeSecret right after CreateSecret. */
const RETRIES = 4;

/**
 * AWS Secrets Manager implementation, built directly on
 * `@aws-sdk/client-secrets-manager`. Secret ARNs are used as `SecretRef`;
 * `SecretVersionRef` is a `${secretRef}/versions/${versionId}` composite,
 * since AWS version IDs aren't independently addressable.
 *
 * TODO: check for idempotency issues before use as part of a resource access
 * lifecycle. Currently only planned for use with GitHub (in-progress). Idempotency
 * issues may be surfaced as part of lifecycle testing.
 *
 */
export const createAwsSecretManagerClient = (
  config: AwsSecretManagerConfig
): SecretManagerClient => {
  const client = new SecretsManagerClient({ region: config.region });

  /** Lists all versions of `secretRef`, including deprecated (unstaged) ones, across all pages. */
  const listSecretVersions = (secretRef: SecretRef) =>
    // TODO: pass pagination params through
    listAllPages<SecretVersionsListEntry>(async (pageToken) => {
      const response = await withErrorMapping(
        () =>
          client.send(
            new ListSecretVersionIdsCommand({
              SecretId: secretRef,
              IncludeDeprecated: true,
              NextToken: pageToken,
            })
          ),
        [
          {
            name: "ResourceNotFoundException",
            toError: (error) =>
              new SecretNotFoundError(secretRef, { cause: error }),
          },
          ...unauthorizedMappings(),
        ]
      );
      return {
        items: response.Versions ?? [],
        nextPageToken: response.NextToken,
      };
    });

  /**
   * Strips every staging label from the version at `ref`, marking it deprecated.
   * This is the closest AWS equivalent to both disabling and permanently destroying
   * a version: AWS has no API to force or observe an immediate hard delete, and
   * purges unstaged versions asynchronously on its own schedule.
   */
  const removeVersionStages = (ref: SecretVersionRef): Promise<void> =>
    withErrorMapping(async () => {
      const { secretRef, versionId } = parseVersionRef(ref);
      const versions = await listSecretVersions(secretRef);
      const version = versions.find((v) => v.VersionId === versionId);
      if (!version) {
        throw new SecretVersionNotFoundError(ref);
      }
      for (const stage of version.VersionStages ?? []) {
        await client.send(
          new UpdateSecretVersionStageCommand({
            SecretId: secretRef,
            VersionStage: stage,
            RemoveFromVersionId: versionId,
          })
        );
      }
    }, unauthorizedMappings());

  return {
    /** Creates a new secret with no initial version. */
    createSecret: async ({ name }) => {
      const created = await withErrorMapping(
        () => client.send(new CreateSecretCommand({ Name: name })),
        [
          {
            name: "ResourceExistsException",
            toError: (error) =>
              new SecretAlreadyExistsError(name, { cause: error }),
          },
          ...unauthorizedMappings(),
        ]
      );
      const described = await withRetry(
        () =>
          withErrorMapping(
            () =>
              client.send(new DescribeSecretCommand({ SecretId: created.ARN })),
            unauthorizedMappings()
          ),
        {
          attempts: RETRIES,
          isRetryable: (error) =>
            getErrorName(error) === "ResourceNotFoundException",
        }
      );
      return toSecretMetadata(described);
    },
    /** Fetches an existing secret using it's name/identifier */
    getSecret: async ({ ref }) => {
      const described = await withErrorMapping(
        () =>
          withRetry(
            () => client.send(new DescribeSecretCommand({ SecretId: ref })),
            {
              attempts: RETRIES,
              isRetryable: (error) =>
                getErrorName(error) === "ResourceNotFoundException",
            }
          ),
        [
          {
            name: "ResourceNotFoundException",
            toError: (error) =>
              new SecretNotFoundError(ref, {
                cause: error,
              }),
          },
          ...unauthorizedMappings(),
        ]
      );
      return toSecretMetadata(described);
    },
    /** Permanently deletes the secret at `ref`, along with all of its versions. */
    deleteSecret: ({ ref }) =>
      withErrorMapping(async () => {
        await client.send(
          new DeleteSecretCommand({
            SecretId: ref,
            // Delete this secret immediately, without the normal recovery window option
            ForceDeleteWithoutRecovery: true,
          })
        );
      }, [
        {
          name: "ResourceNotFoundException",
          toError: (error) => new SecretNotFoundError(ref, { cause: error }),
        },
        ...unauthorizedMappings(),
      ]),

    /** Lists all secrets in the configured region, across all pages. */
    getAllSecrets: async () => {
      const secrets = await listAllPages<SecretListEntry>(async (pageToken) => {
        const response = await withErrorMapping(
          () => client.send(new ListSecretsCommand({ NextToken: pageToken })),
          unauthorizedMappings()
        );
        return {
          items: response.SecretList ?? [],
          nextPageToken: response.NextToken,
        };
      });
      return secrets.map(toSecretMetadata);
    },

    /** Lists all versions of the secret at `ref`, including deprecated ones, across all pages. */
    getSecretVersions: async ({ ref }) => {
      const versions = await listSecretVersions(ref);
      return versions.map((version) => toVersionMetadata(version, ref));
    },

    /**
     * Reads the value and metadata of the secret's current version. Omitting
     * VersionId and VersionStage makes AWS return the version staged as
     * AWSCURRENT. The value is the SecretString as-is, or the SecretBinary
     * decoded into a Buffer.
     */
    getSecretValue: ({ ref }): Promise<SecretValue> =>
      withErrorMapping(async () => {
        const response = await client.send(
          new GetSecretValueCommand({ SecretId: ref })
        );
        const version = toVersionMetadata(response, ref);
        if (response.SecretString !== undefined) {
          return { value: response.SecretString, version };
        }
        if (response.SecretBinary !== undefined) {
          return { value: Buffer.from(response.SecretBinary), version };
        }
        throw new Error(
          `AWS Secrets Manager returned a version with no string or binary value for "${ref}"`
        );
      }, [
        {
          name: "ResourceNotFoundException",
          toError: (error) => new SecretNotFoundError(ref, { cause: error }),
        },
        ...unauthorizedMappings(),
      ]),

    /** Adds a new version to `ref`, becoming AWSCURRENT, with either a random payload of `bytes` size or an explicit `value`. */
    createSecretVersion: ({ ref, ...rest }) =>
      withErrorMapping(async () => {
        const response = await client.send(
          new PutSecretValueCommand({
            SecretId: ref,
            SecretBinary:
              rest.type === "value" ? rest.value : randomBytes(rest.bytes),
          })
        );
        return toVersionMetadata(response, ref);
      }, [
        {
          name: "ResourceNotFoundException",
          toError: (error) => new SecretNotFoundError(ref, { cause: error }),
        },
        ...unauthorizedMappings(),
      ]),

    /** Deprecates the secret version at `ref` by removing all of its staging labels. */
    disableSecretVersion: ({ ref }) => removeVersionStages(ref),

    /**
     * AWS has no API to permanently destroy a single secret version, so this
     * is identical to disableSecretVersion: it removes all staging labels,
     * and AWS purges the now-deprecated version asynchronously on its own schedule.
     */
    deleteSecretVersion: ({ ref }) => removeVersionStages(ref),
  };
};
