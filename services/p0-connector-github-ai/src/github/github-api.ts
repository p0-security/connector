import {
  ConnectorError,
  connectorErrorTypeForHttpStatus,
  createLogger,
} from "@p0security/connector";

const logger = createLogger();

const GITHUB_API_BASE = "https://api.github.com";
/** Pinned `X-GitHub-Api-Version`; bump deliberately. @see https://docs.github.com/en/rest/about-the-rest-api/api-versions */
const GITHUB_API_VERSION = "2026-03-10";
const API_TIMEOUT = 10_000;

/** GitHub permission levels accepted by the installation access token API. */
type AccessLevel = "admin" | "read" | "write";

type Installation = {
  id: number;
  /** The account (org or user) the App is installed on, if GitHub returned one. */
  accountLogin?: string;
};

export type Repository = {
  id: number;
  name: string;
  full_name: string;
  description: string;
};

export type VerifiedInstallation = Required<Installation>;

export type GithubAuth = {
  /**
   * An access credential for GitHub API requests.
   * May either be a signed Github app JWT or an app installation access token
   * The caller is responsible for ensuring the correct kind is passed for each API
   */

  token: string;
  expiresAt?: string;
};

type CreateAccessTokenParams = {
  installationId: number | string;
  /**
   * Repositories to scope the token to. If not present, the access token will be scoped to
   * all repos granted to the installation:
   * https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#create-an-installation-access-token-for-an-app
   */
  repositories?: string[];
  /** Permission map to scope the token to. */
  permissions: Record<string, AccessLevel>;
  /** Must be a signed JWT */
  auth: GithubAuth;
};

type ListRepositoriesParams = {
  per_page: number;
  /** Page number the starts at 1 */
  page: number;
  /** Must be an app installation token */
  auth: GithubAuth;
};

/** Standard headers for a request authenticated with a GitHub App JWT. */
const githubHeaders = (jwt: string) => ({
  Authorization: `Bearer ${jwt}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": GITHUB_API_VERSION,
});

type GithubRequest = RequestInit & { auth: GithubAuth; path: string };

/**
 * Runs a GitHub API call, converting any failure into a {@link ConnectorError}
 * so the framework renders it to the user. Only the HTTP status and GitHub's
 * own message are surfaced — the request (whose headers hold the `Bearer <jwt>`
 * value) is never attached to the error, so the JWT provably cannot leak.
 */
const githubRequest = async <T>(request: GithubRequest): Promise<T> => {
  const { method, path, auth, body } = request;

  let response: Response;
  try {
    response = await fetch(`${GITHUB_API_BASE}${path}`, {
      method,
      headers: {
        ...githubHeaders(auth.token),
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body,
      signal: AbortSignal.timeout(API_TIMEOUT),
    });
  } catch (error) {
    logger.error({ method, path, error }, "GitHub request failed");
    // Network failure, timeout/abort, DNS error — there is no HTTP response.
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `GitHub ${method} ${path} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      payload: {},
    });
  }

  if (!response.ok) {
    const status = response.status;
    const message = await response
      .json()
      .then((data) => (data as { message?: string } | undefined)?.message)
      .catch(() => undefined);
    logger.error(
      { method, path, status, message },
      "GitHub request returned a non-2xx response"
    );
    throw new ConnectorError({
      type: connectorErrorTypeForHttpStatus(status),
      message: `GitHub ${method} ${path} failed (${status}): ${
        message ?? response.statusText
      }`,
      payload: { status, githubMessage: message ?? response.statusText },
    });
  }

  logger.debug(
    { method, path, status: response.status },
    "GitHub request succeeded"
  );
  return (await response.json()) as T;
};

/** Lists every account that has installed the App, authenticated by the App JWT. */
export const getAppInstallations = async (
  auth: GithubAuth
): Promise<Installation[]> => {
  const installations = await githubRequest<
    Array<{ id: number; account: { login?: string } | null }>
  >({
    method: "get",
    path: "/app/installations",
    auth,
  });

  return installations.map(({ id, account }) => ({
    id: id,
    accountLogin: account?.login,
  }));
};

/** Exchanges a GitHub App JWT for an installation access token scoped to the given repositories and permissions. */
export const createAccessToken = async (
  params: CreateAccessTokenParams
): Promise<GithubAuth> => {
  const { installationId, repositories, permissions, auth } = params;
  const { token, expires_at } = await githubRequest<{
    token: string;
    expires_at: string;
  }>({
    method: "post",
    path: `/app/installations/${installationId}/access_tokens`,
    auth,
    body: JSON.stringify({ repositories, permissions }),
  });

  return {
    token,
    expiresAt: expires_at,
  };
};

export const listRepositories = async (
  params: ListRepositoriesParams
): Promise<{ total: number; repositories: Repository[] }> => {
  const { per_page, page, auth } = params;
  const { total_count, repositories } = await githubRequest<{
    total_count: number;
    repositories: Repository[];
  }>({
    method: "get",
    path: `/installation/repositories?${new URLSearchParams({
      per_page: String(per_page),
      page: String(page),
    }).toString()}`,
    auth,
  });
  return { total: total_count, repositories };
};
