import {
  ConnectorError,
  connectorErrorTypeForHttpStatus,
  createLogger,
} from "@p0security/connector";

const logger = createLogger();

const API_TIMEOUT = 10_000;

export type DatadogAuth = {
  /** Datadog site, e.g. "datadoghq.com" */
  site: string;
  apiKey: string;
  appKey: string;
};

export type DatadogKey = {
  id: string;
  key: string;
};

type DatadogRequest = {
  auth: DatadogAuth;
  // Fetch uppercases only some method names, and not PATCH, so pass them
  // uppercase.
  method: "DELETE" | "GET" | "PATCH" | "POST";
  path: string;
  body?: unknown;
};

type KeyResponse = { data: { id: string; attributes: { key: string } } };

type PermissionsResponse = {
  data: { attributes: { name: string; display_name?: string } }[];
};

type ErrorBody = { errors?: (string | { title?: string; detail?: string })[] };

/** Datadog's error text: `errors` holds strings, or JSON:API objects. */
const errorMessage = async (response: Response) =>
  await response
    .json()
    .then(
      (data) =>
        (data as ErrorBody | undefined)?.errors
          ?.map((error) =>
            typeof error === "string" ? error : (error.detail ?? error.title)
          )
          .join("; ") || undefined
    )
    .catch(() => undefined);

/**
 * Runs a Datadog API call, converting any failure into a {@link ConnectorError}
 * so the framework renders it to the user. Only the HTTP status and Datadog's
 * own message are surfaced. The request, whose headers hold both keys, is never
 * attached to the error.
 *
 * @returns The parsed JSON body, or `undefined` for a 204 response
 */
const datadogRequest = async <T>(request: DatadogRequest): Promise<T> => {
  const { auth, method, path, body } = request;

  let response: Response;
  try {
    response = await fetch(`https://api.${auth.site}${path}`, {
      method,
      headers: {
        "DD-API-KEY": auth.apiKey,
        "DD-APPLICATION-KEY": auth.appKey,
        Accept: "application/json",
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(API_TIMEOUT),
    });
  } catch (error) {
    logger.error({ method, path, error }, "Datadog request failed");
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `Datadog ${method} ${path} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      payload: {},
    });
  }

  if (!response.ok) {
    const { status } = response;
    const message = await errorMessage(response);
    logger.error(
      { method, path, status, message },
      "Datadog request returned a non-2xx response"
    );
    throw new ConnectorError({
      type: connectorErrorTypeForHttpStatus(status),
      message: `Datadog ${method} ${path} failed (${status}): ${
        message ?? response.statusText
      }`,
      payload: { status },
    });
  }

  logger.debug(
    { method, path, status: response.status },
    "Datadog request succeeded"
  );
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
};

const isNotFound = (error: unknown) =>
  error instanceof ConnectorError && error.data.type === "object_not_found";

/** Runs a delete, and treats a key that is already gone as deleted. */
const deleteIdempotently = async (request: DatadogRequest) => {
  try {
    await datadogRequest<undefined>(request);
  } catch (error) {
    if (isNotFound(error)) return;
    throw error;
  }
};

const accessTokensPath = (serviceAccountId: string) =>
  `/api/v2/service_accounts/${encodeURIComponent(serviceAccountId)}/access_tokens`;

/** Creates a service access token for a service account, limited to `scopes`. */
export const createServiceAccessToken = async (
  auth: DatadogAuth,
  params: { serviceAccountId: string; name: string; scopes: string[] }
): Promise<DatadogKey> => {
  const { serviceAccountId, name, scopes } = params;
  const { data } = await datadogRequest<KeyResponse>({
    auth,
    method: "POST",
    path: accessTokensPath(serviceAccountId),
    body: {
      data: { type: "service_access_tokens", attributes: { name, scopes } },
    },
  });
  return { id: data.id, key: data.attributes.key };
};

type TokenListResponse = {
  data: { id: string; attributes: { name: string } }[];
};

const TOKEN_PAGE_SIZE = 100;

/** Finds the id of a service account's access token by its exact name.
 *
 * @returns `undefined` when no token has that name
 * @throws {ConnectorError} when more than one token has that name
 */
export const findServiceAccessTokenId = async (
  auth: DatadogAuth,
  params: { serviceAccountId: string; name: string }
): Promise<string | undefined> => {
  const { serviceAccountId, name } = params;
  const matches: string[] = [];
  for (let page = 0; ; page++) {
    const query = new URLSearchParams({
      filter: name,
      "page[size]": String(TOKEN_PAGE_SIZE),
      "page[number]": String(page),
    });
    const { data } = await datadogRequest<TokenListResponse>({
      auth,
      method: "GET",
      path: `${accessTokensPath(serviceAccountId)}?${query.toString()}`,
    });
    // The filter is not an exact match, so compare names here.
    matches.push(
      ...data
        .filter((token) => token.attributes.name === name)
        .map(({ id }) => id)
    );
    if (data.length < TOKEN_PAGE_SIZE) break;
  }
  if (matches.length > 1) {
    throw new ConnectorError({
      type: "unknown",
      message: `More than one Datadog access token is named "${name}"`,
      payload: { count: matches.length },
    });
  }
  return matches[0];
};

/** Replaces the scopes of a service access token. The token value does not
 * change. */
export const updateServiceAccessTokenScopes = async (
  auth: DatadogAuth,
  params: { serviceAccountId: string; tokenId: string; scopes: string[] }
) => {
  const { serviceAccountId, tokenId, scopes } = params;
  await datadogRequest<unknown>({
    auth,
    method: "PATCH",
    path: `${accessTokensPath(serviceAccountId)}/${encodeURIComponent(tokenId)}`,
    body: {
      data: {
        id: tokenId,
        type: "service_access_tokens",
        attributes: { scopes },
      },
    },
  });
};

/** Revokes a service access token. A token that does not exist is not an
 * error. */
export const revokeServiceAccessToken = async (
  auth: DatadogAuth,
  params: { serviceAccountId: string; tokenId: string }
) =>
  await deleteIdempotently({
    auth,
    method: "DELETE",
    path: `${accessTokensPath(params.serviceAccountId)}/${encodeURIComponent(params.tokenId)}`,
  });

/** Lists the permissions that a user's or service account's roles grant. */
export const listUserPermissions = async (
  auth: DatadogAuth,
  userId: string
): Promise<{ name: string; displayName?: string }[]> => {
  const { data } = await datadogRequest<PermissionsResponse>({
    auth,
    method: "GET",
    path: `/api/v2/users/${encodeURIComponent(userId)}/permissions`,
  });
  return data.map(({ attributes }) => ({
    name: attributes.name,
    displayName: attributes.display_name,
  }));
};
