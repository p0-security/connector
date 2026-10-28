/** The values the connector's tests share. */

export const ORGANIZATION_ID = "0b5a3c1e-6f2d-4e8a-9c7b-1d2e3f4a5b6c";

export const ORGANIZATION_NAME = "Acme";

/** The API key's ID, Basic auth's user name, as the Cloud console shows it. */
export const KEY_ID = "mFhGq3LrT9xKp2Wz8YbN";

/**
 * The key's UUID (`ApiKey.id`), which an endpoint's `apiKeyIds` takes. The
 * connector finds it among the organization's keys by `keySuffix`.
 */
export const KEY_UUID = "7d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";

/** The key secret, with a marker a leak check can search for. */
export const KEY_SECRET = "4b1dSENTINELch7e9q2xKeySecret0a8c";

export const API_KEY = { keyId: KEY_ID, keySecret: KEY_SECRET };

/** The secret's value, as the customer stores it. */
export const STORED_KEY = JSON.stringify(API_KEY);

export const AWS_SECRET = {
  manager: "aws" as const,
  secretId: "clickhouse-api-key",
  region: "us-west-2",
};

export const GCP_SECRET = {
  manager: "gcp" as const,
  secretId: "clickhouse-api-key",
  projectId: "acme-prod",
};

export const CREDENTIALS = {
  organizationId: ORGANIZATION_ID,
  apiKeySecret: AWS_SECRET,
};

export const SERVICE_ID = "5f0e9d8c-7b6a-4954-8a32-1f0e9d8c7b6a";

export const OTHER_SERVICE_ID = "6a1f0e9d-8c7b-4a65-9b43-2a1f0e9d8c7b";

/** The requestor, whose domain `ALLOWED_PATTERN` allows. */
export const EMAIL = "alice@acme.com";

export const ALLOWED_PATTERN = "^acme\\.com$";

/**
 * How long a test that loads an entry point may take. Loading one loads the
 * framework and the entry point's whole dependency graph, which is under a
 * second on an idle machine and has taken a minute on a busy one.
 */
export const LOAD_TIMEOUT_MS = 120_000;
