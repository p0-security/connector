/** The values the connector's tests share. */

/** A service account token, with a marker a leak check can search for. */
export const TOKEN = "ops_SENTINEL7f3a9c";

export const AWS_SECRET = {
  manager: "aws" as const,
  secretId: "op-token",
  region: "us-west-2",
};

export const GCP_SECRET = {
  manager: "gcp" as const,
  secretId: "op-token",
  projectId: "acme-prod",
};

/** A 1Password vault ID: 26 lowercase base32 characters. */
export const VAULT = "ghtz3jvcc6dqmzc53d3r3eskge";

/** A 1Password item ID, in the same form. */
export const ITEM = "ydahjnlxhogqzmkogdbr5yo2nu";

export const CREDENTIALS = { vault: VAULT, tokenSecret: AWS_SECRET };

/** The requestor, whose domain `ALLOWED_PATTERN` allows. */
export const EMAIL = "alice@acme.com";

export const ALLOWED_PATTERN = "^acme\\.com$";

/**
 * How long a test that loads an entry point may take. Loading one loads the
 * framework and the entry point's whole dependency graph, which is under a
 * second on an idle machine and has taken a minute on a busy one.
 */
export const LOAD_TIMEOUT_MS = 120_000;
