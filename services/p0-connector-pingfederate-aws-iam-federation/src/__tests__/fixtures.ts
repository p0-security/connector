import { ConnectorError, createLogger } from "@p0security/connector-core";

export const AWS_SECRET = {
  manager: "aws" as const,
  region: "us-west-2",
  secretId: "pingfederate-scim-password",
};

export const SCIM_PASSWORD = " scim pa55word ";

export const APP_INPUT = {
  pingFederateUrl: "https://sso.example.com:9031",
  scimUsername: "p0",
  scimPassword: AWS_SECRET,
  roleAttribute: "awsRole",
};

export const logger = createLogger();
logger.level = "silent";

/** The `ConnectorError` `run` fails with. */
export const connectorError = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    if (error instanceof ConnectorError) return error;
    throw error;
  }
  throw new Error("expected the call to throw");
};
