/** The values the connector's tests share. */

/** An organization access token, with a marker a leak check can search for. */
export const TOKEN = "dckr_oat_SENTINEL7f3a9c";

export const AWS_SECRET = {
  manager: "aws" as const,
  secretId: "docker-oat",
  region: "us-west-2",
};

export const GCP_SECRET = {
  manager: "gcp" as const,
  secretId: "docker-oat",
  projectId: "acme-prod",
};

export const CREDENTIALS = { org: "acme", tokenSecret: AWS_SECRET };

/** The requestor, whose domain `ALLOWED_PATTERN` allows. */
export const EMAIL = "alice@acme.com";

export const ALLOWED_PATTERN = "^acme\\.com$";

/** The requestor's Docker account. */
export const UUID = "0ab70deb-065a-43fc-acd5-5d48caa945d8";

/**
 * How long a test that loads an entry point may take. Loading one loads the
 * framework and the entry point's whole dependency graph, which is under a
 * second on an idle machine and has taken a minute on a busy one.
 */
export const LOAD_TIMEOUT_MS = 120_000;
