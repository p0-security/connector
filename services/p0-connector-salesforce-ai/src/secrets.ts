import { ConnectorError } from "@p0security/connector-core";
import type {
  SecretManagerClient,
  SecretRef,
} from "@p0security/connector-secret-manager-client";

/** Reads the provisioner app's consumer secret. The secret value is the
 * consumer secret itself. */
export const getConsumerSecret = async (
  secrets: SecretManagerClient,
  ref: SecretRef
): Promise<string> => {
  const { value } = await secrets.getSecretValue({ ref });
  const consumerSecret =
    typeof value === "string" ? value : value.toString("utf8");
  if (consumerSecret.length === 0) {
    throw new ConnectorError({
      type: "validation_error",
      message: "The Salesforce provisioner consumer secret is empty",
      payload: {},
    });
  }
  return consumerSecret;
};
