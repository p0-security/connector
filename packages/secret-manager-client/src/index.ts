export type {
  SecretRef,
  SecretVersionRef,
  SecretMetadata,
  SecretVersionState,
  VersionMetadata,
  SecretPayload,
  SecretValue,
  CreateSecretParams,
  GetSecretVersionsParams,
  GetSecretValueParams,
  CreateSecretVersionParams,
  DisableSecretVersionParams,
  DeleteSecretVersionParams,
  SecretManagerClient,
  SecretManagerProviderConfig,
} from "./types.ts";
export {
  SecretManagerError,
  SecretAlreadyExistsError,
  SecretNotFoundError,
  SecretVersionNotFoundError,
  UnauthorizedError,
  NotImplementedError,
} from "./errors.ts";
export { createSecretManagerClient } from "./factory.ts";
