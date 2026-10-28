import {
  ConnectorError,
  connectorErrorTypeForHttpStatus,
  createLogger,
} from "@p0security/connector-core";

import type { AtlasProjectRole } from "./roles.ts";

const logger = createLogger();

const API_TIMEOUT = 10_000;

const TOKEN_URL = "https://cloud.mongodb.com/api/oauth/token";

const API_BASE = "https://cloud.mongodb.com/api/atlas/v2";

const API_VERSION = "application/vnd.atlas.2025-03-12+json";

// The API's maximum page size.
const PAGE_SIZE = 500;

/** The shortest secret lifetime, in hours, that Atlas accepts by default. An
 * organization can raise it. */
const SECRET_LIFETIME_HOURS = 8;

export type ServiceAccountCredentials = {
  clientId: string;
  clientSecret: string;
};

export type McpConfig = {
  mcpConfigId: string;
  mcpConfigName: string;
  clientId: string;
  roles: string[];
};

export type McpConfigSecret = { id: string; createdAt: string };

type TokenResponse = { access_token: string };

type Page<T> = { results: T[]; totalCount?: number };

type ErrorBody = {
  detail?: string;
  error_description?: string;
  error?: unknown;
};

const errorMessage = async (response: Response) =>
  await response
    .json()
    .then((data) => {
      const { detail, error_description, error } = (data ?? {}) as ErrorBody;
      return (
        detail ??
        error_description ??
        (typeof error === "string" ? error : undefined)
      );
    })
    .catch(() => undefined);

/**
 * Runs an Atlas call, converting any failure into a {@link ConnectorError} so
 * the framework renders it to the user. Only the HTTP status and Atlas's own
 * message are surfaced. The request, whose headers or body can hold a secret,
 * is never logged or attached to the error.
 *
 * @returns The response, or `undefined` for a 404 when `allowNotFound` is set
 */
const atlasRequest = async (
  label: string,
  url: string,
  init: RequestInit,
  { allowNotFound = false }: { allowNotFound?: boolean } = {}
): Promise<Response | undefined> => {
  let response: Response;
  try {
    response = await fetch(url, {
      ...init,
      signal: AbortSignal.timeout(API_TIMEOUT),
    });
  } catch (error) {
    logger.error({ label, error }, "Atlas request failed");
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `Atlas ${label} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      payload: {},
    });
  }

  if (allowNotFound && response.status === 404) return undefined;
  if (!response.ok) {
    const { status } = response;
    const message = await errorMessage(response);
    logger.error(
      { label, status, message },
      "Atlas request returned a non-2xx response"
    );
    throw new ConnectorError({
      type: connectorErrorTypeForHttpStatus(status),
      message: `Atlas ${label} failed (${status}): ${
        message ?? response.statusText
      }`,
      payload: { status },
    });
  }

  logger.debug({ label, status: response.status }, "Atlas request succeeded");
  return response;
};

/** Gets an access token for a service account with the client credentials
 * grant. Atlas tokens last 1 hour. */
export const requestToken = async (
  credentials: ServiceAccountCredentials,
  label = "token request"
): Promise<string> => {
  const basic = Buffer.from(
    `${credentials.clientId}:${credentials.clientSecret}`
  ).toString("base64");
  const response = await atlasRequest(label, TOKEN_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ grant_type: "client_credentials" }),
  });
  const { access_token } = (await response!.json()) as TokenResponse;
  return access_token;
};

/** Calls the Atlas Administration API as the admin service account. */
export const newAtlasClient = (token: string, projectId: string) => {
  const projectUrl = `${API_BASE}/groups/${encodeURIComponent(projectId)}`;

  const call = async <T>(
    label: string,
    method: "DELETE" | "GET" | "PATCH" | "POST",
    path: string,
    { body, allowNotFound }: { body?: unknown; allowNotFound?: boolean } = {}
  ): Promise<T | undefined> => {
    const response = await atlasRequest(
      label,
      `${projectUrl}${path}`,
      {
        method,
        headers: {
          Accept: API_VERSION,
          Authorization: `Bearer ${token}`,
          ...(body ? { "Content-Type": API_VERSION } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      },
      { allowNotFound }
    );
    if (!response || response.status === 204) return undefined;
    const text = await response.text();
    return text ? (JSON.parse(text) as T) : undefined;
  };

  const listAll = async <T>(label: string, path: string): Promise<T[]> => {
    const items: T[] = [];
    for (let pageNum = 1; ; pageNum++) {
      const page = await call<Page<T>>(
        label,
        "GET",
        `${path}?itemsPerPage=${PAGE_SIZE}&pageNum=${pageNum}`
      );
      const results = page?.results ?? [];
      items.push(...results);
      if (results.length < PAGE_SIZE) return items;
    }
  };

  const configPath = (mcpConfigId: string) =>
    `/mcpConfigs/${encodeURIComponent(mcpConfigId)}`;

  return {
    findMcpConfig: async (name: string): Promise<McpConfig | undefined> =>
      (await listAll<McpConfig>("MCP configuration list", "/mcpConfigs")).find(
        ({ mcpConfigName }) => mcpConfigName === name
      ),

    createMcpConfig: async (
      name: string,
      roles: AtlasProjectRole[]
    ): Promise<McpConfig> =>
      (await call<McpConfig>(
        "MCP configuration create",
        "POST",
        "/mcpConfigs",
        { body: { mcpConfigName: name, roles } }
      ))!,

    setMcpConfigRoles: async (mcpConfigId: string, roles: AtlasProjectRole[]) =>
      await call("MCP configuration update", "PATCH", configPath(mcpConfigId), {
        body: { roles },
      }),

    /** Deletes the configuration and its secrets, which ends their tokens at
     * once. */
    deleteMcpConfig: async (mcpConfigId: string) =>
      await call(
        "MCP configuration delete",
        "DELETE",
        `${configPath(mcpConfigId)}?cascading=true`,
        { allowNotFound: true }
      ),

    listMcpConfigSecrets: async (
      mcpConfigId: string
    ): Promise<McpConfigSecret[]> =>
      await listAll<McpConfigSecret>(
        "MCP configuration secret list",
        `${configPath(mcpConfigId)}/secrets`
      ),

    /** @returns The new secret; Atlas returns its value only here */
    createMcpConfigSecret: async (
      mcpConfigId: string
    ): Promise<McpConfigSecret & { secret: string }> =>
      (await call<McpConfigSecret & { secret: string }>(
        "MCP configuration secret create",
        "POST",
        `${configPath(mcpConfigId)}/secrets`,
        { body: { secretExpiresAfterHours: SECRET_LIFETIME_HOURS } }
      ))!,

    /** Deletes one secret, which ends its tokens at once. */
    deleteMcpConfigSecret: async (mcpConfigId: string, secretId: string) =>
      await call(
        "MCP configuration secret delete",
        "DELETE",
        `${configPath(mcpConfigId)}/secrets/${encodeURIComponent(secretId)}`,
        { allowNotFound: true }
      ),
  };
};

export type AtlasClient = ReturnType<typeof newAtlasClient>;
