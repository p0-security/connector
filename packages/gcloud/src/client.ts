import { bigquery } from "@googleapis/bigquery";
import { cloudresourcemanager } from "@googleapis/cloudresourcemanager";
// Deep-import the v1 submodule directly, bypassing the package's barrel
// (which also re-exports alpha/beta), since we only use v1 and the barrel's
// alpha/beta type definitions dwarf everything else in this file's type-check.
import { compute_v1 } from "@googleapis/compute/build/v1.js";
import { iam } from "@googleapis/iam";
import { iap } from "@googleapis/iap";
import { secretmanager } from "@googleapis/secretmanager";
import { sqladmin } from "@googleapis/sqladmin";
import { storage } from "@googleapis/storage";
import type { OAuth2Client } from "google-auth-library";
import { GoogleAuth } from "google-auth-library";

export type GcloudClients = Awaited<ReturnType<typeof createClients>>;

export const CLOUDSQL_LOGIN_SCOPE =
  "https://www.googleapis.com/auth/sqlservice.login";
const BIGQUERY_SCOPE = "https://www.googleapis.com/auth/bigquery";
const CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

export const getGoogleAuth = (scopes: string[]) =>
  new GoogleAuth({ scopes: scopes });

/*
 * Resolves the email of the runtime service account (via Application Default
 * Credentials). Resolving the identity does not mint a scoped token, so no
 * scopes are required.
 */
export const getServiceAccountEmail = async (): Promise<string> => {
  const { client_email: clientEmail } = await getGoogleAuth(
    []
  ).getCredentials();
  if (!clientEmail) {
    throw new Error("Could not resolve the runtime service account email");
  }
  return clientEmail;
};

/** Bundles all GCP SDK clients with shared authn
 *
 * To access a client from an instance of this class (e.g.,
 * to access the IAM client):
 * ```
 * const clients = createClients();
 * const { iam } = await clients;
 * ```
 */
export const createClients = async (auth?: GoogleAuth | OAuth2Client) => {
  if (!auth) {
    const targetScopes = [BIGQUERY_SCOPE, CLOUD_PLATFORM_SCOPE];

    auth = new GoogleAuth({
      scopes: targetScopes,
    });
  }

  return {
    auth: auth,
    bq: bigquery({ version: "v2", auth }),
    compute: new compute_v1.Compute({ auth }),
    crm: cloudresourcemanager({ version: "v3", auth }),
    iam: iam({ version: "v1", auth }),
    iap: iap({ version: "v1", auth }),
    secretManager: secretmanager({ version: "v1", auth }),
    sqladmin: sqladmin({ version: "v1", auth }),
    storage: storage({ version: "v1", auth }),
  };
};
