import type { SecretManagementSecurityPerimeter } from "./client.ts";
import type { SecretManagementSchema } from "./schema.ts";

/**
 * The primitives a specific connector must implement — lower-level, less
 * constrained building blocks than {@link SecretManagementSecurityPerimeter}.
 * {@link buildSecretManagementSecurityPerimeter} folds these into that perimeter.
 *
 * @summary The low-level primitives a connector implements to deliver a secret-management security perimeter.
 */
export type SecretManagementConnectorPrimitives<
  Schema extends SecretManagementSchema,
> = {
  listSecrets: (
    query: Schema["ListSecretsQuery"]
  ) => Promise<Schema["ListSecretsResponse"]>;

  getSecretMetadata: (
    secretId: Schema["SecretId"]
  ) => Promise<Schema["SecretMetadata"]>;

  createNewVersion: (
    secretId: Schema["SecretId"]
  ) => Promise<Schema["VersionMetadata"]>;

  disableVersion: (versionId: Schema["VersionId"]) => Promise<void>;

  deleteVersion: (versionId: Schema["VersionId"]) => Promise<void>;

  getInstallValidation: () => Promise<Schema["InstallValidation"]>;
};

/** @deprecated Use {@link SecretManagementConnectorPrimitives}. */
export type SecretManagementConnectorContract<
  Schema extends SecretManagementSchema,
> = SecretManagementConnectorPrimitives<Schema>;

/** @deprecated Use {@link SecretManagementConnectorPrimitives}. */
export type SecretManagementMethods<Schema extends SecretManagementSchema> =
  SecretManagementConnectorPrimitives<Schema>;

/**
 * Builds a {@link SecretManagementSecurityPerimeter} from a connector's
 * {@link SecretManagementConnectorPrimitives}.
 *
 * @summary Builds a secret-management security perimeter from a connector's implementation contract.
 */
export const buildSecretManagementSecurityPerimeter = <
  Schema extends SecretManagementSchema,
>(
  methods: SecretManagementConnectorPrimitives<Schema>
): SecretManagementSecurityPerimeter<Schema> => ({
  listSecrets: async ({ query }) => methods.listSecrets(query),
  getSecretMetadata: async ({ secretId }) =>
    methods.getSecretMetadata(secretId),
  createNewVersion: async ({ secretId }) => methods.createNewVersion(secretId),
  disableVersion: async ({ versionId }) => {
    await methods.disableVersion(versionId);
    return null;
  },
  deleteVersion: async ({ versionId }) => {
    await methods.deleteVersion(versionId);
    return null;
  },
  getInstallValidation: async () => methods.getInstallValidation(),
});

/** @deprecated Use {@link buildSecretManagementSecurityPerimeter}. */
export const secretManagementImpl = buildSecretManagementSecurityPerimeter;
