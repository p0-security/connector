import { DefaultAzureCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";
import type { SecretProperties } from "@azure/keyvault-secrets";

import {
  NotImplementedError,
  SecretNotFoundError,
  UnauthorizedError,
} from "../errors.ts";
import type {
  SecretManagerClient,
  SecretManagerProviderConfig,
  SecretMetadata,
  SecretRef,
  SecretValue,
  SecretVersionRef,
  VersionMetadata,
} from "../types.ts";

type AzureSecretManagerConfig = Extract<
  SecretManagerProviderConfig,
  { provider: "azure" }
>;

/** Credential errors thrown by `@azure/identity` when no token can be obtained. */
const CREDENTIAL_ERROR_NAMES = [
  "AggregateAuthenticationError",
  "AuthenticationError",
  "CredentialUnavailableError",
];

/** Extracts the HTTP status code from a Key Vault `RestError`, if present. */
const getStatusCode = (error: unknown): number | undefined => {
  if (typeof error !== "object" || error === null) return undefined;
  const statusCode = (error as { statusCode?: unknown }).statusCode;
  return typeof statusCode === "number" ? statusCode : undefined;
};

type ErrorMapping = {
  matches: (error: unknown) => boolean;
  toError: (error: unknown) => Error;
};

/** 401/403 and credential failures -> UnauthorizedError, shared by all Key Vault calls. */
const unauthorizedMappings = (): ErrorMapping[] => [
  {
    matches: (error) =>
      error instanceof Error && CREDENTIAL_ERROR_NAMES.includes(error.name),
    toError: (error) => new UnauthorizedError("azure", { cause: error }),
  },
  {
    matches: (error) => getStatusCode(error) === 401,
    toError: (error) => new UnauthorizedError("azure", { cause: error }),
  },
  {
    matches: (error) => getStatusCode(error) === 403,
    toError: (error) => new UnauthorizedError("azure", { cause: error }),
  },
];

/** 404 -> SecretNotFoundError for the secret at `ref`. */
const notFoundMapping = (ref: SecretRef): ErrorMapping => ({
  matches: (error) => getStatusCode(error) === 404,
  toError: (error) => new SecretNotFoundError(ref, { cause: error }),
});

/** Runs `fn`, rethrowing as a mapped error type if the error matches one of `mappings`. */
const withErrorMapping = async <T>(
  fn: () => Promise<T>,
  mappings: ErrorMapping[]
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    const mapping = mappings.find((m) => m.matches(error));
    throw mapping ? mapping.toError(error) : error;
  }
};

/**
 * Drains a Key Vault paged iterator. The SDK follows each page's `nextLink`
 * itself; `listAllPages` can't drive it, because the pages that
 * `byPage()` yields don't carry a `continuationToken`.
 */
const collect = async <T>(iterator: AsyncIterable<T>): Promise<T[]> => {
  const items: T[] = [];
  for await (const item of iterator) {
    items.push(item);
  }
  return items;
};

/**
 * Key Vault properties describe a secret's current version, so `createTime`
 * is when that version was created, not when the secret first was.
 */
const toSecretMetadata = (properties: SecretProperties): SecretMetadata => ({
  ref: properties.name as SecretRef,
  name: properties.name,
  createTime: properties.createdOn ?? new Date(0),
});

/**
 * Key Vault version IDs are scoped to their secret, so SecretVersionRef is a
 * composite of the secret name and the version ID.
 */
const toVersionRef = (secretRef: SecretRef, version: string) =>
  `${secretRef}/versions/${version}` as SecretVersionRef;

/**
 * Converts Key Vault secret properties into the client's VersionMetadata
 * shape. Key Vault has no "destroyed" version state: a version is only ever
 * enabled or disabled.
 */
const toVersionMetadata = (
  properties: SecretProperties,
  secretRef: SecretRef
): VersionMetadata => {
  if (!properties.version) {
    throw new Error("Azure Key Vault returned a secret with no version");
  }
  return {
    ref: toVersionRef(secretRef, properties.version),
    secretRef,
    state: properties.enabled === false ? "disabled" : "enabled",
    createTime: properties.createdOn ?? new Date(0),
  };
};

/**
 * Azure Key Vault implementation, built on `@azure/keyvault-secrets` and
 * `DefaultAzureCredential`. On Azure, the Connector authenticates as its
 * user-assigned managed identity, which `DefaultAzureCredential` selects
 * through `AZURE_CLIENT_ID`.
 *
 * `SecretRef` is the bare secret name, since each client is bound to one vault.
 * Names pass through unvalidated: Key Vault allows only letters, digits and
 * `-`, and mapping other names onto that is the caller's job.
 *
 * Only reads are implemented. The Connector's identity holds `Key Vault
 * Secrets User` on its vault, which can't write, and Key Vault can't hold a
 * secret with no version, which `createSecret` promises.
 */
export const createKeyVaultSecretManagerClient = (
  config: AzureSecretManagerConfig
): SecretManagerClient => {
  const client = new SecretClient(
    config.vaultUrl,
    new DefaultAzureCredential()
  );

  return {
    createSecret: async () => {
      throw new NotImplementedError("createSecret");
    },

    /** Fetches the secret's current version, since Key Vault has no metadata-only read of a secret. */
    getSecret: ({ ref }) =>
      withErrorMapping(async () => {
        const secret = await client.getSecret(ref);
        return toSecretMetadata(secret.properties);
      }, [notFoundMapping(ref), ...unauthorizedMappings()]),

    deleteSecret: async () => {
      throw new NotImplementedError("deleteSecret");
    },

    /** Lists all secrets in the configured vault, across all pages. */
    getAllSecrets: () =>
      withErrorMapping(async () => {
        const secrets = await collect(client.listPropertiesOfSecrets());
        return secrets.map(toSecretMetadata);
      }, unauthorizedMappings()),

    /** Lists all versions of the secret at `ref`, across all pages. */
    getSecretVersions: ({ ref }) =>
      withErrorMapping(async () => {
        const versions = await collect(
          client.listPropertiesOfSecretVersions(ref)
        );
        return versions.map((version) => toVersionMetadata(version, ref));
      }, [notFoundMapping(ref), ...unauthorizedMappings()]),

    /**
     * Reads the value and metadata of the secret's current version. Key Vault
     * stores values as strings, so the value is always a `string`.
     */
    getSecretValue: ({ ref }): Promise<SecretValue> =>
      withErrorMapping(async () => {
        const secret = await client.getSecret(ref);
        if (secret.value === undefined) {
          throw new Error(
            `Azure Key Vault returned a version with no value for "${ref}"`
          );
        }
        return {
          value: secret.value,
          version: toVersionMetadata(secret.properties, ref),
        };
      }, [notFoundMapping(ref), ...unauthorizedMappings()]),

    createSecretVersion: async () => {
      throw new NotImplementedError("createSecretVersion");
    },

    disableSecretVersion: async () => {
      throw new NotImplementedError("disableSecretVersion");
    },

    deleteSecretVersion: async () => {
      throw new NotImplementedError("deleteSecretVersion");
    },
  };
};
