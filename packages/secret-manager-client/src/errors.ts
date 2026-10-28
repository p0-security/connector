import type {
  SecretManagerProviderConfig,
  SecretRef,
  SecretVersionRef,
} from "./types.ts";

/**
 * Base class for all errors thrown by a `SecretManagerClient`. Provider
 * implementations should catch vendor-specific SDK errors and re-throw as one
 * of the subclasses below, so that callers don't need to branch on provider.
 */
export abstract class SecretManagerError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** Thrown by `createSecret` when a secret with the requested name already exists. */
export class SecretAlreadyExistsError extends SecretManagerError {
  readonly secretName: string;

  constructor(secretName: string, options?: { cause?: unknown }) {
    super(`Secret "${secretName}" already exists`, options);
    this.secretName = secretName;
  }
}

/** Thrown when a `SecretRef` does not match any secret known to the provider. */
export class SecretNotFoundError extends SecretManagerError {
  readonly ref: SecretRef;

  constructor(ref: SecretRef, options?: { cause?: unknown }) {
    super(`Secret "${ref}" does not exist`, options);
    this.ref = ref;
  }
}

/** Thrown when a `SecretVersionRef` does not match any version known to the provider. */
export class SecretVersionNotFoundError extends SecretManagerError {
  readonly ref: SecretVersionRef;

  constructor(ref: SecretVersionRef, options?: { cause?: unknown }) {
    super(`Secret version "${ref}" does not exist`, options);
    this.ref = ref;
  }
}

/** Thrown when the client cannot authenticate against the provider's API. */
export class UnauthorizedError extends SecretManagerError {
  readonly provider: SecretManagerProviderConfig["provider"];

  constructor(
    provider: SecretManagerProviderConfig["provider"],
    options?: { cause?: unknown }
  ) {
    super(
      `Not authorized to access the "${provider}" secret manager API`,
      options
    );
    this.provider = provider;
  }
}

/** Thrown by provider implementations that haven't been built out yet. */
export class NotImplementedError extends SecretManagerError {
  readonly method: string;

  constructor(method: string) {
    super(`"${method}" is not yet implemented for this provider`);
    this.method = method;
  }
}
