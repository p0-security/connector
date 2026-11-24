import type { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import type {
  SecretManagerProviderConfig,
  SecretPayload,
  SecretRef,
} from "@p0security/connector-secret-manager-client";

import type { Connect } from "./postgres/client.ts";

/**
 * Opens the shared secret manager client, of which the connector reads a
 * manager secret's value, and creates and writes a grant secret.
 */
export type ConnectSecretManager = (
  config: SecretManagerProviderConfig
) => Promise<{
  getSecretValue: (params: {
    ref: SecretRef;
  }) => Promise<{ value: SecretPayload }>;
  createSecret: (params: { name: string }) => Promise<unknown>;
  createSecretVersion: (params: {
    ref: SecretRef;
    type: "value";
    value: Buffer<ArrayBuffer>;
  }) => Promise<unknown>;
}>;

/** What stands in for the connector's environment, AWS, PostgreSQL and
 * randomness in tests. */
export type Dependencies = {
  /** The connector's environment. Its `AWS_REGION`, which Lambda sets, is
   * the region the connector runs in. */
  env?: NodeJS.ProcessEnv;
  connectSecretManager?: ConnectSecretManager;
  /** The SDK client that describes a grant secret, in a region. */
  secretsManagerSdk?: (region: string) => Pick<SecretsManagerClient, "send">;
  connect?: Connect;
  /** Where a grant login's password and its verifier's salt come from. */
  randomBytes?: (size: number) => Buffer;
};
