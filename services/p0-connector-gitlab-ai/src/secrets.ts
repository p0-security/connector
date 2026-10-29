import { ConnectorError } from "@p0security/connector-core";
import type {
  SecretManagerClient,
  SecretRef,
} from "@p0security/connector-secret-manager-client";

/** Reads the admin token that P0 uses to manage grant service accounts. */
export const getAdminToken = async (
  secrets: SecretManagerClient,
  ref: SecretRef
): Promise<string> => {
  const { value } = await secrets.getSecretValue({ ref });
  const token = (
    typeof value === "string" ? value : value.toString("utf8")
  ).trim();
  if (!token) {
    throw new ConnectorError({
      type: "validation_error",
      message: "The GitLab admin token secret is empty",
      payload: {},
    });
  }
  return token;
};
