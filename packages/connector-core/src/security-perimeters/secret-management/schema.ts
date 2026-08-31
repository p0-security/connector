import type { JsonValue } from "type-fest";

import type { SecretManagementSecurityPerimeter } from "./client.ts";
import type { SecretManagementConnectorPrimitives } from "./implementation.ts";
import type { SecretManagementParsers } from "./parsers.ts";

/**
 * The types used by {@link SecretManagementSecurityPerimeter}.
 */
export type SecretManagementSchema = {
  /** The identifier of a secret. */
  SecretId: JsonValue;
  /** A secret's metadata, excluding its version data. */
  SecretMetadata: JsonValue;
  /** The identifier of a secret version. */
  VersionId: JsonValue;
  /** A secret version's metadata. */
  VersionMetadata: JsonValue;
  /** The result of validating that the connector is correctly installed. */
  InstallValidation: JsonValue;
  /** A query used to list secrets. */
  ListSecretsQuery: JsonValue;
  /** The result of listing secrets. */
  ListSecretsResponse: JsonValue;
};

/**
 * Extracts the {@link SecretManagementSchema} from a SecretManagement related type.
 */
export type SecretManagementSchemaOf<T> =
  T extends SecretManagementSecurityPerimeter<infer Types>
    ? Types
    : T extends SecretManagementConnectorPrimitives<infer Types>
      ? Types
      : T extends SecretManagementParsers<infer Types>
        ? Types
        : never;
