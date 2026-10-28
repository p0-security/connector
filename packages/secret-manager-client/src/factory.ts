import { createAwsSecretManagerClient } from "./providers/aws.ts";
import { createGsmSecretManagerClient } from "./providers/gsm.ts";
import { createKeyVaultSecretManagerClient } from "./providers/keyvault.ts";
import type {
  SecretManagerClient,
  SecretManagerProviderConfig,
} from "./types.ts";

export const createSecretManagerClient = async (
  config: SecretManagerProviderConfig
): Promise<SecretManagerClient> => {
  switch (config.provider) {
    case "gcp":
      return createGsmSecretManagerClient(config);
    case "aws":
      return createAwsSecretManagerClient(config);
    case "azure":
      return createKeyVaultSecretManagerClient(config);
  }
};
