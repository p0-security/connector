/**
 * Opaque identifier for a secret. The concrete shape is provider-specific
 * (e.g. a GSM resource name, an AWS Secrets Manager ARN, or a Key Vault
 * secret name). Callers should only ever pass back a ref they were previously
 * given by this client, never construct or parse one directly.
 */
export type SecretRef = string & { readonly __brand: "SecretRef" };

/**
 * Opaque identifier for a specific version of a secret. The concrete shape
 * is provider-specific (e.g. a GSM numeric version string, or an AWS version
 * ID plus stage label). Callers should only ever pass back a ref they were
 * previously given by this client, never construct or parse one directly.
 */
export type SecretVersionRef = string & {
  readonly __brand: "SecretVersionRef";
};

export type SecretMetadata = {
  ref: SecretRef;
  name: string;
  createTime: Date;
};

export type SecretVersionState = "destroyed" | "disabled" | "enabled";

export type VersionMetadata = {
  ref: SecretVersionRef;
  secretRef: SecretRef;
  state: SecretVersionState;
  createTime: Date;
};

export type CreateSecretParams = {
  name: string;
};

export type GetSecretParams = {
  ref: SecretRef;
};

export type DeleteSecretParams = {
  ref: SecretRef;
};

export type GetSecretVersionsParams = {
  ref: SecretRef;
};

/**
 * The decoded payload of a secret version: a `string` for text secrets, or a
 * `Buffer` for binary ones (e.g. versions created by `createSecretVersion`).
 */
export type SecretPayload = Buffer | string;

/** A secret version's decoded payload together with the version it was read from. */
export type SecretValue = {
  value: SecretPayload;
  version: VersionMetadata;
};

export type GetSecretValueParams = {
  ref: SecretRef;
};

export type CreateSecretVersionParams = {
  ref: SecretRef;
} & (
  | {
      type: "random";
      bytes: number;
    }
  | {
      type: "value";
      value: Buffer<ArrayBuffer>;
    }
);

export type DisableSecretVersionParams = {
  ref: SecretVersionRef;
};

export type DeleteSecretVersionParams = {
  ref: SecretVersionRef;
};

export type SecretManagerClient = {
  /** Creates a secret with no initial version; throws `SecretAlreadyExistsError` if the name is taken. */
  createSecret: (params: CreateSecretParams) => Promise<SecretMetadata>;
  deleteSecret: (params: DeleteSecretParams) => Promise<void>;
  getSecret: (params: GetSecretParams) => Promise<SecretMetadata>;
  /** Lists all secrets visible to this client. */
  getAllSecrets: () => Promise<SecretMetadata[]>;
  /** Lists all versions of a given secret. */
  getSecretVersions: (
    params: GetSecretVersionsParams
  ) => Promise<VersionMetadata[]>;
  /** Reads the value and metadata of the secret's latest (current) version. */
  getSecretValue: (params: GetSecretValueParams) => Promise<SecretValue>;
  /** Creates a new version of a secret, either with a random value of a given size or an explicit value. */
  createSecretVersion: (
    params: CreateSecretVersionParams
  ) => Promise<VersionMetadata>;
  disableSecretVersion: (params: DisableSecretVersionParams) => Promise<void>;
  deleteSecretVersion: (params: DeleteSecretVersionParams) => Promise<void>;
};

export type SecretManagerProviderConfig =
  | { provider: "aws"; region: string }
  | { provider: "azure"; vaultUrl: string }
  | { provider: "gcp"; projectId: string };
