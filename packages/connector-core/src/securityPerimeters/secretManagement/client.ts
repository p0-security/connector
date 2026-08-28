import type { TRPCClient } from "@trpc/client";
import { createTRPCClient } from "@trpc/client";

import { action } from "../common/client.ts";
import type { SecurityPerimeter } from "../common/securityPerimeter.ts";
import type { SecretManagementParsers } from "./parsers.ts";
import type { SecretManagementSchema } from "./schema.ts";
import type { SecretManagementRouter } from "./trpc.ts";

/**
 * The security perimeter for a secret-management connector: list, read
 * metadata for, version, disable, and delete secrets.
 *
 * @summary The security perimeter for a secret-management connector.
 */
export type SecretManagementSecurityPerimeter<
  Schema extends SecretManagementSchema = SecretManagementSchema,
> = SecurityPerimeter<{
  listSecrets: (params: {
    query: Schema["ListSecretsQuery"];
  }) => Promise<Schema["ListSecretsResponse"]>;

  getSecretMetadata: (params: {
    secretId: Schema["SecretId"];
  }) => Promise<Schema["SecretMetadata"]>;

  createNewVersion: (params: {
    secretId: Schema["SecretId"];
  }) => Promise<Schema["VersionMetadata"]>;

  disableVersion: (params: { versionId: Schema["VersionId"] }) => Promise<null>;

  deleteVersion: (params: { versionId: Schema["VersionId"] }) => Promise<null>;

  getInstallValidation: (
    params: Record<string, never>
  ) => Promise<Schema["InstallValidation"]>;
}>;

/** @deprecated Use {@link SecretManagementSecurityPerimeter}. */
export type SecretManagementClient<
  Schema extends SecretManagementSchema = SecretManagementSchema,
> = SecretManagementSecurityPerimeter<Schema>;

export type SecretManagementEndpoint = keyof SecretManagementSecurityPerimeter;

/**
 * Builds a {@link SecretManagementSecurityPerimeter} that parses raw tRPC
 * responses into a validated {@link Schema}. Split from
 * {@link newSecretManagementClient} so it can be given an
 * already-constructed tRPC client.
 */
const newSecretManagementClientInner = <Schema extends SecretManagementSchema>(
  parsers: SecretManagementParsers<Schema>,
  client: Pick<
    TRPCClient<SecretManagementRouter<Schema>>,
    SecretManagementEndpoint
  >
): SecretManagementSecurityPerimeter<Schema> => {
  return {
    listSecrets: action(client.listSecrets.query, parsers.listSecretsResponse),
    getSecretMetadata: action(
      client.getSecretMetadata.query,
      parsers.secretMetadata
    ),
    createNewVersion: action(
      client.createNewVersion.mutate,
      parsers.versionMetadata
    ),
    disableVersion: action(client.disableVersion.mutate, () => null),
    deleteVersion: action(client.deleteVersion.mutate, () => null),
    getInstallValidation: action(
      client.getInstallValidation.query,
      parsers.installValidation
    ),
  };
};

/**
 * Creates a {@link SecretManagementSecurityPerimeter} backed by a tRPC connection to the connector.
 */
export const newSecretManagementClient = <
  Schema extends SecretManagementSchema,
>(
  parsers: SecretManagementParsers<Schema>,
  opts: Parameters<typeof createTRPCClient<SecretManagementRouter<Schema>>>[0]
): SecretManagementSecurityPerimeter<Schema> =>
  newSecretManagementClientInner(
    parsers,
    createTRPCClient<SecretManagementRouter<Schema>>(opts)
  );
