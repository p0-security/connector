import { ConnectorError } from "@p0security/connector";
import type {
  SecretManagerClient,
  SecretRef,
} from "@p0security/secret-manager-client";

/** Reads the admin service account's client secret. The secret value is the client
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
      message: "The Atlas service account client secret is empty",
      payload: {},
    });
  }
  return clientSecret;
};
