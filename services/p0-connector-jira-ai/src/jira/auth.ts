import {
  ConnectorError,
  type ConnectorErrorType,
  type Logger,
  connectorErrorTypeForHttpStatus,
} from "@p0security/connector";
import { z } from "zod";

import type { Site } from "../install/definition.ts";
import { readSecretString } from "../secrets.ts";
import { callAtlassian } from "./atlassian-call.ts";

export const TOKEN_URL = "https://auth.atlassian.com/oauth/token";

/** How long before its expiry a cached admin token is replaced. */
export const REFRESH_MARGIN_MS = 60_000;

/**
 * An Atlassian 400 is a request it refused as invalid, such as an account
 * that can't hold a Jira role. The rest follow the framework's mapping.
 */
export const errorTypeForStatus = (status: number): ConnectorErrorType =>
  status === 400 ? "validation_error" : connectorErrorTypeForHttpStatus(status);

export type ClientCredentials = { clientId: string; clientSecret: string };

const tokenResponse = z.object({
  access_token: z.string().min(1),
  expires_in: z.number().positive(),
});

// Atlassian's OAuth error code, such as `access_denied`. Only a code of this
// shape is quoted: the rest of the body is Atlassian's to choose.
const errorCode = z.object({ error: z.string().regex(/^[a-z_]{1,64}$/) });

/**
 * Exchanges an OAuth client's credentials for a two-legged (2LO) access token
 * at Atlassian's token endpoint (`grant_type=client_credentials`).
 *
 * `who` names the client for a message, such as "the Jira admin client".
 * `deadline` is the connector request's (see `requestDeadline`). Neither the
 * secret nor the token goes into an error or a log line.
 */
export const exchangeClientCredentials = async (
  { clientId, clientSecret }: ClientCredentials,
  who: string,
  deadline: number,
  logger: Logger
): Promise<{ accessToken: string; expiresInSeconds: number }> => {
  const response = await callAtlassian({
    url: TOKEN_URL,
    init: {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
      }),
    },
    // An exchange changes nothing, so a repeat is safe.
    repeatable: true,
    operation: `sign in as ${who}`,
    deadline,
    logger,
  }).catch((error: unknown) => {
    logger.warn(
      { error: error instanceof Error ? error.name : "unknown" },
      "the Atlassian token request failed"
    );
    // The request's budget ran out, and the error says so.
    if (error instanceof ConnectorError) throw error;
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `The connector couldn't reach Atlassian to sign in as ${who}. Try again.`,
      payload: {},
    });
  });

  if (!response.ok) {
    const { status } = response;
    const code = errorCode.safeParse(
      await response.json().catch(() => undefined)
    );
    const quoted = code.success ? ` (${code.data.error})` : "";
    logger.warn(
      { status, error: code.success ? code.data.error : undefined },
      "Atlassian refused the token request"
    );
    // Atlassian answers a bad client ID or secret with 400 `invalid_client`.
    const refused =
      status === 401 ||
      status === 403 ||
      (code.success && code.data.error === "invalid_client");
    throw new ConnectorError({
      type: refused ? "insufficient_privileges" : errorTypeForStatus(status),
      message: refused
        ? `Atlassian refused the client credentials of ${who}${quoted}. Check that the credential still exists in Atlassian, and that its secret in Google Secret Manager holds the current client secret. If P0 has the wrong client ID, ask your P0 admin to delete the site in P0 and add it again.`
        : `Atlassian's token endpoint failed for ${who} with ${status}${quoted}. Try again in a few minutes.`,
      payload: { status },
    });
  }

  const parsed = tokenResponse.safeParse(
    await response.json().catch(() => undefined)
  );
  if (!parsed.success) {
    throw new ConnectorError({
      type: "unknown",
      message: `Atlassian's token endpoint answered for ${who} without an access token. Try again, and contact support@p0.dev if it keeps happening.`,
      payload: {},
    });
  }
  return {
    accessToken: parsed.data.access_token,
    expiresInSeconds: parsed.data.expires_in,
  };
};

type CachedToken = { accessToken: string; expiresAt: number };

// Admin tokens by site and admin client. Module scope, so a warm instance
// reuses a token across calls.
const adminTokens = new Map<string, CachedToken>();

// The secret's location is part of the key, so a call that names another
// secret for the same client reads that secret instead of borrowing a token.
const cacheKey = ({ cloudId, adminClientId, adminSecret }: Site) =>
  JSON.stringify([
    cloudId,
    adminClientId,
    adminSecret.projectId,
    adminSecret.secretId,
  ]);

/**
 * The admin service account's access token for a site. The cache keeps it
 * until {@link REFRESH_MARGIN_MS} before it expires. On a miss, the connector
 * reads the admin client secret from its secret and exchanges it for a new
 * token, both before the connector request's `deadline`.
 */
export const getAdminToken = async (
  site: Site,
  logger: Logger,
  deadline: number
): Promise<string> => {
  const key = cacheKey(site);
  const cached = adminTokens.get(key);
  if (cached !== undefined && Date.now() < cached.expiresAt - REFRESH_MARGIN_MS)
    return cached.accessToken;

  const clientSecret = await readSecretString(
    site.adminSecret,
    "the Jira admin client secret",
    logger,
    deadline
  );
  const { accessToken, expiresInSeconds } = await exchangeClientCredentials(
    { clientId: site.adminClientId, clientSecret },
    "the Jira admin client",
    deadline,
    logger
  );
  adminTokens.set(key, {
    accessToken,
    expiresAt: Date.now() + expiresInSeconds * 1000,
  });
  return accessToken;
};

/** Drops a site's cached admin token, such as after Jira refused it. */
export const forgetAdminToken = (site: Site) => {
  adminTokens.delete(cacheKey(site));
};

/** Drops every cached admin token. For tests. */
export const forgetAllAdminTokens = () => {
  adminTokens.clear();
};
