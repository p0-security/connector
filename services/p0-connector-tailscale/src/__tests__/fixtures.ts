/** The values the connector's tests share. */

/** The OAuth client's secret, with a marker a leak check can search for. */
export const CLIENT_SECRET = "tskey-client-SENTINEL4b2e8d";

export const CLIENT_ID = "kAbCdEf1CNTRL";

export const FEDERATED_CLIENT_ID = "Tz8TefihCR11DEVEL-kqc11MVpwu11DEVEL";

export const TAILNET = "T1234CNTRL";

export const AWS_SECRET = {
  manager: "aws" as const,
  secretId: "tailscale-oauth-client",
  region: "us-west-2",
};

export const GCP_SECRET = {
  manager: "gcp" as const,
  secretId: "tailscale-oauth-client",
  projectId: "acme-prod",
};

export const VAULT_CREDENTIAL = {
  kind: "vault" as const,
  clientId: CLIENT_ID,
  secret: AWS_SECRET,
};

export const FEDERATED_CREDENTIAL = {
  kind: "federated" as const,
  clientId: FEDERATED_CLIENT_ID,
};

/** The tailnet's credentials, as every call carries them. */
export const CREDENTIALS = {
  tailnet: TAILNET,
  credential: VAULT_CREDENTIAL,
};

/** The requestor. */
export const EMAIL = "alice@acme.com";

/**
 * The identity token the fake cloud mints for `audience`: a JWT-shaped
 * string carrying the audience, with a marker a leak check can search for.
 */
export const identityTokenFor = (audience: string): string =>
  `eyJhbGciOiJFUzM4NCJ9.${Buffer.from(
    JSON.stringify({ aud: audience, sub: "arn:aws:iam::123:role/p0" })
  ).toString("base64url")}.SENTINELsig`;

/** The fake cloud identity: mints {@link identityTokenFor} the audience asked for. */
export const fakeIdentityToken = async (audience: string): Promise<string> =>
  identityTokenFor(audience);

/**
 * How long a test that loads an entry point may take. Loading one loads the
 * framework and the entry point's whole dependency graph.
 */
export const LOAD_TIMEOUT_MS = 120_000;
