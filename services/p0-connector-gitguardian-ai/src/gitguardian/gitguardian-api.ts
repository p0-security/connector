import {
  ConnectorError,
  connectorErrorTypeForHttpStatus,
  createLogger,
} from "@p0security/connector-core";

const logger = createLogger();

const API_TIMEOUT = 10_000;

/** API host per GitGuardian cloud region. */
export const GitguardianApiHosts = {
  us: "api.gitguardian.com",
  eu: "api.eu1.gitguardian.com",
} as const;

export type GitguardianRegion = keyof typeof GitguardianApiHosts;

export type GitguardianAuth = {
  region: GitguardianRegion;
  token: string;
};

/** An API token's record, as `/v1/api_tokens` returns it. */
export type ApiToken = {
  id: string;
  name: string;
  type: "personal_access_token" | "service_account";
  scopes: string[];
  member_id: number | null;
  workspace_id: number;
  /** `null` for a token that never expires. */
  expire_at: string | null;
  status: "active" | "expired" | "revoked";
};

type GitguardianRequest = {
  auth: GitguardianAuth;
  method: "DELETE" | "GET" | "POST";
  path: string;
  body?: unknown;
};

/** GitGuardian's error text, e.g. `{"detail":"Invalid API key."}`. */
const errorDetail = async (response: Response) =>
  await response
    .json()
    .then((data) => (data as { detail?: unknown } | undefined)?.detail)
    .then((detail) => (typeof detail === "string" ? detail : undefined))
    .catch(() => undefined);

/**
 * Runs a GitGuardian API call, converting any failure into a
 * {@link ConnectorError}. The payload keeps GitGuardian's `detail`, because
 * some failures share a status and differ only by it. The request, whose
 * header holds the token, is never logged or attached to the error.
 *
 * @returns The parsed JSON body, or `undefined` for a 204 response, and the
 * `Link` header that list endpoints page with
 */
const gitguardianResponse = async <T>(
  request: GitguardianRequest
): Promise<{ data: T; link: string | null }> => {
  const { auth, method, path, body } = request;

  let response: Response;
  try {
    response = await fetch(
      `https://${GitguardianApiHosts[auth.region]}${path}`,
      {
        method,
        headers: {
          Authorization: `Token ${auth.token}`,
          Accept: "application/json",
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(API_TIMEOUT),
      }
    );
  } catch (error) {
    logger.error({ method, path, error }, "GitGuardian request failed");
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `GitGuardian ${method} ${path} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      payload: {},
    });
  }

  if (!response.ok) {
    const { status } = response;
    const detail = await errorDetail(response);
    logger.error(
      { method, path, status, detail },
      "GitGuardian request returned a non-2xx response"
    );
    throw new ConnectorError({
      type: connectorErrorTypeForHttpStatus(status),
      message: `GitGuardian ${method} ${path} failed (${status}): ${
        detail ?? response.statusText
      }`,
      payload: { status, ...(detail !== undefined ? { detail } : {}) },
    });
  }

  logger.debug(
    { method, path, status: response.status },
    "GitGuardian request succeeded"
  );
  const link = response.headers?.get("link") ?? null;
  if (response.status === 204) return { data: undefined as T, link };
  return { data: (await response.json()) as T, link };
};

const gitguardianRequest = async <T>(request: GitguardianRequest) =>
  (await gitguardianResponse<T>(request)).data;

/**
 * The path and query of a `Link` header's `rel="next"` URL, or `null` on the
 * last page. A URL on any other host is refused, so that a header cannot send
 * the token elsewhere.
 */
const nextPagePath = (link: string | null, region: GitguardianRegion) => {
  const match = link?.match(/<([^>]+)>;\s*rel="next"/);
  if (!match) return null;
  const url = new URL(match[1]);
  if (url.host !== GitguardianApiHosts[region]) {
    throw new ConnectorError({
      type: "unknown",
      message: `GitGuardian sent a next page on another host: ${url.host}`,
      payload: { host: url.host },
    });
  }
  return `${url.pathname}${url.search}`;
};

/** The calling token's own record. Needs no scope. */
export const getCurrentToken = (auth: GitguardianAuth) =>
  gitguardianRequest<ApiToken>({
    auth,
    method: "GET",
    path: "/v1/api_tokens/self",
  });

/**
 * Mints a token for the calling token's owner. `lifetime` is in whole days,
 * and GitGuardian requires it. The response is the only time the key is shown.
 */
export const mintToken = (
  auth: GitguardianAuth,
  body: {
    name: string;
    type: ApiToken["type"];
    scopes: string[];
    lifetime: number;
  }
) =>
  gitguardianRequest<ApiToken & { key: string }>({
    auth,
    method: "POST",
    path: "/v1/api_tokens",
    body,
  });

/** A member's active tokens, across every page. Needs `api_tokens:read`. */
export const listActiveTokens = async (
  auth: GitguardianAuth,
  memberId: number
): Promise<ApiToken[]> => {
  const tokens: ApiToken[] = [];
  let path: string | null =
    `/v1/api_tokens?member_id=${memberId}&status=active&per_page=100`;
  while (path) {
    const { data, link }: { data: ApiToken[]; link: string | null } =
      await gitguardianResponse<ApiToken[]>({ auth, method: "GET", path });
    tokens.push(...data);
    path = nextPagePath(link, auth.region);
  }
  return tokens;
};

/** Revokes a token by id. Needs `api_tokens:write`. */
export const deleteToken = (auth: GitguardianAuth, id: string) =>
  gitguardianRequest<undefined>({
    auth,
    method: "DELETE",
    path: `/v1/api_tokens/${encodeURIComponent(id)}`,
  });
