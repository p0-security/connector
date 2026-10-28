import {
  ConnectorError,
  connectorErrorTypeForHttpStatus,
  createLogger,
} from "@p0security/connector";

import type { PagerdutyRegion } from "./regions.ts";

const logger = createLogger();

const API_TIMEOUT = 10_000;

const TOKEN_URL = "https://identity.pagerduty.com/oauth/token";

const mcpHosts: Record<PagerdutyRegion, string> = {
  us: "mcp.pagerduty.com",
  eu: "mcp.eu.pagerduty.com",
};

// The empty scope, OpenID, and Classic OAuth's account-wide scopes.
const NON_RESOURCE_SCOPES = new Set(["none", "openid", "read", "write"]);

// PagerDuty's MCP server refuses a token without users.read.
const ALWAYS_REQUESTED_SCOPES = ["users.read"];

export type AppCredentials = {
  clientId: string;
  clientSecret: string;
};

type TokenResponse = { access_token: string; scope: string };

type ProtectedResourceResponse = { scopes_supported: string[] };

type ErrorBody = { error?: string; error_description?: string };

const errorMessage = async (response: Response) =>
  await response
    .json()
    .then((data) => {
      const { error, error_description } = (data ?? {}) as ErrorBody;
      return error_description ?? error;
    })
    .catch(() => undefined);

/**
 * Runs a PagerDuty call, converting any failure into a {@link ConnectorError}
 * so the framework renders it to the user. Only the HTTP status and
 * PagerDuty's own message are surfaced. The request, whose body can hold the
 * client secret, is never logged or attached to the error.
 */
const pagerdutyRequest = async <T>(
  label: string,
  url: string,
  init: RequestInit
): Promise<T> => {
  let response: Response;
  try {
    response = await fetch(url, {
      ...init,
      signal: AbortSignal.timeout(API_TIMEOUT),
    });
  } catch (error) {
    logger.error({ label, error }, "PagerDuty request failed");
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `PagerDuty ${label} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      payload: {},
    });
  }

  if (!response.ok) {
    const { status } = response;
    const message = await errorMessage(response);
    logger.error(
      { label, status, message },
      "PagerDuty request returned a non-2xx response"
    );
    throw new ConnectorError({
      type: connectorErrorTypeForHttpStatus(status),
      message: `PagerDuty ${label} failed (${status}): ${
        message ?? response.statusText
      }`,
      payload: { status },
    });
  }

  logger.debug(
    { label, status: response.status },
    "PagerDuty request succeeded"
  );
  return (await response.json()) as T;
};

/** Gets an app token that holds only `scopes`, plus `users.read`, in one
 * account, with the client credentials grant.
 *
 * @returns The access token
 * @throws {ConnectorError} when the app does not hold every requested scope
 */
export const requestAppToken = async (
  credentials: AppCredentials,
  params: { region: PagerdutyRegion; subdomain: string; scopes: string[] }
): Promise<string> => {
  const { region, subdomain } = params;
  const scopes = [...new Set([...params.scopes, ...ALWAYS_REQUESTED_SCOPES])];
  const { access_token, scope } = await pagerdutyRequest<TokenResponse>(
    "token request",
    TOKEN_URL,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: credentials.clientId,
        client_secret: credentials.clientSecret,
        scope: [`as_account-${region}.${subdomain}`, ...scopes].join(" "),
      }),
    }
  );
  // PagerDuty leaves out a scope that the app does not hold, and does not fail.
  const granted = new Set(scope.split(" "));
  const missing = scopes.filter((s) => !granted.has(s));
  if (missing.length > 0) {
    logger.error({ missing }, "PagerDuty left out requested scopes");
    throw new ConnectorError({
      type: "validation_error",
      message: `PagerDuty did not grant ${missing.join(", ")}. Make sure that the PagerDuty app holds these scopes.`,
      payload: { missing: missing.join(" ") },
    });
  }
  return access_token;
};

/** Lists the resource scopes that PagerDuty's MCP server publishes for a
 * region. A token request can get only those that the app also holds. */
export const listSupportedScopes = async (
  region: PagerdutyRegion
): Promise<string[]> => {
  const { scopes_supported } =
    await pagerdutyRequest<ProtectedResourceResponse>(
      "scope list",
      `https://${mcpHosts[region]}/.well-known/oauth-protected-resource/mcp`,
      { method: "GET", headers: { Accept: "application/json" } }
    );
  return scopes_supported.filter((scope) => !NON_RESOURCE_SCOPES.has(scope));
};
