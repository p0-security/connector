import type { JsonValue } from "type-fest";
import { z } from "zod";

import type { JSONParser, OneArgFuncParameter } from "../../parsers.ts";
import type { SecretManagementSecurityPerimeter } from "./client.ts";
import type { SecretManagementSchema } from "./schema.ts";

/**
 * Parsers to enforce type safety for SecretManagement data and method inputs.
 */
export type SecretManagementParsers<Schema extends SecretManagementSchema> = {
  kind: "secret-management";
} & {
  [T in keyof Schema as Uncapitalize<T & string>]: JSONParser<Schema[T]>;
} & {
  [T in keyof SecretManagementSecurityPerimeter<Schema> as Uncapitalize<
    T & string
  >]: JSONParser<
    OneArgFuncParameter<SecretManagementSecurityPerimeter<Schema>[T]>
  >;
};

/**
 * Creates {@link SecretManagementParsers} from Zod schemas.
 *
 * @summary Creates {@link SecretManagementParsers} from Zod schemas.
 * @category High-Level
 */
export const newZodSecretManagementParsers = <
  SecretIdSchema extends z.ZodType<JsonValue>,
  SecretMetadataSchema extends z.ZodType<JsonValue>,
  VersionIdSchema extends z.ZodType<JsonValue>,
  VersionMetadataSchema extends z.ZodType<JsonValue>,
  InstallValidationSchema extends z.ZodType<JsonValue>,
  ListSecretsQuerySchema extends z.ZodType<JsonValue>,
  ListSecretsResponseSchema extends z.ZodType<JsonValue>,
>(schemas: {
  secretId: SecretIdSchema;
  secretMetadata: SecretMetadataSchema;
  versionId: VersionIdSchema;
  versionMetadata: VersionMetadataSchema;
  installValidation: InstallValidationSchema;
  listSecretsQuery: ListSecretsQuerySchema;
  listSecretsResponse: ListSecretsResponseSchema;
}): SecretManagementParsers<{
  SecretId: z.output<SecretIdSchema>;
  SecretMetadata: z.output<SecretMetadataSchema>;
  VersionId: z.output<VersionIdSchema>;
  VersionMetadata: z.output<VersionMetadataSchema>;
  InstallValidation: z.output<InstallValidationSchema>;
  ListSecretsQuery: z.output<ListSecretsQuerySchema>;
  ListSecretsResponse: z.output<ListSecretsResponseSchema>;
}> => {
  const {
    secretId,
    secretMetadata,
    versionId,
    versionMetadata,
    installValidation,
    listSecretsQuery,
    listSecretsResponse,
  } = schemas;
  const zodParser = <T extends Record<string, z.ZodType>>(obj: T) =>
    z.object(obj).required().parse;

  return {
    kind: "secret-management",
    secretId: secretId.parse,
    secretMetadata: secretMetadata.parse,
    versionId: versionId.parse,
    versionMetadata: versionMetadata.parse,
    installValidation: installValidation.parse,
    listSecretsQuery: listSecretsQuery.parse,
    listSecretsResponse: listSecretsResponse.parse,
    listSecrets: zodParser({ query: listSecretsQuery }),
    getSecretMetadata: zodParser({ secretId }),
    createNewVersion: zodParser({ secretId }),
    disableVersion: zodParser({ versionId }),
    deleteVersion: zodParser({ versionId }),
    getInstallValidation: zodParser({}),
  };
};
