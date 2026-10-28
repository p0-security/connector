/** The values the connector's tests share. */

/** The client secret, with a marker a leak check can search for. */
export const CLIENT_SECRET = "auth0_secret_SENTINEL4b2e8d";

export const CLIENT_ID = "AbCdEf0123456789AbCdEf0123456789";

export const TENANT = "acme.us.auth0.com";

export const AWS_SECRET = {
  manager: "aws" as const,
  secretId: "auth0-client-secret",
  region: "us-west-2",
};

export const GCP_SECRET = {
  manager: "gcp" as const,
  secretId: "auth0-client-secret",
  projectId: "acme-prod",
};

export const CREDENTIALS = {
  tenant: TENANT,
  clientId: CLIENT_ID,
  clientSecret: AWS_SECRET,
};

/** The requestor, whose domain `ALLOWED_PATTERN` allows. */
export const EMAIL = "alice@acme.com";

export const ALLOWED_PATTERN = "^acme\\.com$";

/**
 * How long a test that loads an entry point may take. Loading one loads the
 * framework and the entry point's whole dependency graph, which is under a
 * second on an idle machine and has taken a minute on a busy one.
 */
export const LOAD_TIMEOUT_MS = 120_000;
