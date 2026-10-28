import { ConnectorError } from "@p0security/connector-core";
import type {
  SecretManagerClient,
  SecretRef,
} from "@p0security/secret-manager-client";

/** Reads the Scoped OAuth app's client secret. The secret value is the client
 * secret itself. */
export const getClientSecret = async (
  secrets: SecretManagerClient,
  ref: SecretRef
): Promise<string> => {
  const { value } = await secrets.getSecretValue({ ref });
  const clientSecret =
    typeof value === "string" ? value : value.toString("utf8");
  if (clientSecret.length === 0) {
    throw new ConnectorError({
      type: "validation_error",
      message: "The PagerDuty client secret is empty",
      payload: {},
    });
  }
  return clientSecret;
};
