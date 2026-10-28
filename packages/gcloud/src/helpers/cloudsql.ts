import { CLOUDSQL_LOGIN_SCOPE, getGoogleAuth } from "../client.ts";

/*
 * Cloud SQL IAM database authentication uses a short-lived OAuth2 access token
 * (minted for the connector's runtime service account via Application Default
 * Credentials) as the database password. We connect over direct IP to the
 * host/port supplied by the lifecycle
 */
export const fetchDbPassword = async (): Promise<string> => {
  const auth = getGoogleAuth([CLOUDSQL_LOGIN_SCOPE]);
  const token = await auth.getAccessToken();
  if (!token) {
    throw new Error("Failed to mint a Cloud SQL IAM access token");
  }
  return token;
};
