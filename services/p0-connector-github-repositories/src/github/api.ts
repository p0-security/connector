import { ConnectorError, createLogger } from "@p0security/connector";

const logger = createLogger();

const GITHUB_API_BASE = "https://api.github.com";
/** Pinned `X-GitHub-Api-Version`; bump deliberately. @see https://docs.github.com/en/rest/about-the-rest-api/api-versions */
const GITHUB_API_VERSION = "2026-03-10";
const API_TIMEOUT = 10_000;

/** GitHub App permission levels, lowest first. */
export const ACCESS_LEVELS = ["read", "write", "admin"] as const;
export type AccessLevel = (typeof ACCESS_LEVELS)[number];

/** A GitHub App permission map, as installations report it and as tokens request it. */
export type Permissions = Record<string, AccessLevel>;

export type Installation = {
  id: number;
  permissions: Permissions;
  repositorySelection: "all" | "selected";
  /** An org owner suspended the installation: GitHub still returns it, but refuses to mint tokens for it. */
  suspended: boolean;
};

export type Repository = {
  name: string;
  full_name: string;
};

type Method = "DELETE" | "GET" | "POST" | "PUT";

/**
 * A GitHub API call that failed.
 *
 * Carries only what the connector needs to classify the failure. The request,
 * whose headers hold the JWT or installation token, is never attached.
 */
export class GitHubError extends Error {
  /** The HTTP status, or `undefined` when GitHub was never reached. */
  readonly status: number | undefined;
  /** GitHub's own messages: the top-level `message`, then each `errors[]` entry (its `message`, or the entry itself when it's a string). */
  readonly githubMessages: string[];
  /** `X-Accepted-GitHub-Permissions`: the permissions the call would have needed. */
  readonly acceptedPermissions: string | undefined;
  /** For a GraphQL error, the field it was raised on, e.g. `repository`. */
  readonly graphqlPath: string | undefined;

  constructor(params: {
    method: Method;
    path: string;
    status: number | undefined;
    githubMessages: string[];
    acceptedPermissions?: string;
    graphqlPath?: string;
  }) {
    const { method, path, status, githubMessages } = params;
    super(
      `GitHub ${method} ${path} failed${status === undefined ? "" : ` (${status})`}: ${
        githubMessages[0] ?? "no message"
      }`
    );
    this.name = "GitHubError";
    this.status = status;
    this.githubMessages = githubMessages;
    this.acceptedPermissions = params.acceptedPermissions;
    this.graphqlPath = params.graphqlPath;
  }
}

type GitHubRequest = {
  method: Method;
  path: string;
  /** A signed App JWT or an installation token; each endpoint says which. */
  token: string;
  body?: unknown;
};

type GitHubResponse<T> = { status: number; data: T };

// `errors[]` entries are usually objects with a `message`, but GitHub also
// sends plain strings there.
const messagesOf = (data: any, fallback: string): string[] => {
  const messages = [
    data?.message,
    ...(Array.isArray(data?.errors)
      ? data.errors.map((error: any) =>
          typeof error === "string" ? error : error?.message
        )
      : []),
  ].filter((message): message is string => typeof message === "string");
  return messages.length > 0 ? messages : [fallback];
};

const readBody = async (response: Response): Promise<unknown> => {
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

const githubRequest = async <T>({
  method,
  path,
  token,
  body,
}: GitHubRequest): Promise<GitHubResponse<T>> => {
  let response: Response;
  try {
    response = await fetch(`${GITHUB_API_BASE}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(API_TIMEOUT),
    });
  } catch (error) {
    // Network failure, timeout/abort, DNS error: there is no HTTP response.
    logger.error({ method, path, error }, "GitHub request failed");
    throw new GitHubError({
      method,
      path,
      status: undefined,
      githubMessages: [error instanceof Error ? error.message : String(error)],
    });
  }

  const data = await readBody(response);
  if (!response.ok) {
    const error = new GitHubError({
      method,
      path,
      status: response.status,
      githubMessages: messagesOf(data, response.statusText),
      acceptedPermissions:
        response.headers.get("x-accepted-github-permissions") ?? undefined,
    });
    logger.warn(
      {
        method,
        path,
        status: error.status,
        githubMessages: error.githubMessages,
        acceptedPermissions: error.acceptedPermissions,
      },
      "GitHub request returned a non-2xx response"
    );
    throw error;
  }

  logger.debug(
    { method, path, status: response.status },
    "GitHub request succeeded"
  );
  return { status: response.status, data: data as T };
};

/**
 * One URL path segment.
 *
 * `encodeURIComponent` leaves `.` and `..` alone, and `fetch` would resolve
 * them, so `login: ".."` would turn `/repos/o/r/collaborators/..` into
 * `/repos/o/r/`. The input schemas already refuse them; this refuses them
 * again at the point where it matters.
 */
const segment = (value: string): string => {
  if (value === "." || value === "..") {
    throw new ConnectorError({
      type: "validation_error",
      message: `"${value}" isn't a valid GitHub name.`,
      payload: { segment: value },
    });
  }
  return encodeURIComponent(value);
};

// GraphQL reports failures in the body of a 200, typed rather than numbered.
const GRAPHQL_ERROR_STATUS: Partial<Record<string, number>> = {
  NOT_FOUND: 404,
  FORBIDDEN: 403,
  RATE_LIMITED: 429,
};
// A GraphQL error with no type, or one not listed above (e.g. "Something went
// wrong while executing your query"), is GitHub failing to answer. It's
// reported as a bad gateway rather than the 200 it arrived in, which would
// read as a success that somehow failed.
const GRAPHQL_UNTYPED_ERROR_STATUS = 502;

/** Runs a GraphQL query. Any error in the response throws, even alongside partial data. */
export const githubGraphql = async <T>(
  token: string,
  query: string,
  variables: Record<string, unknown>
): Promise<T> => {
  const { data } = await githubRequest<{
    data?: T;
    errors?: { type?: string; message?: string; path?: string[] }[];
  }>({ method: "POST", path: "/graphql", token, body: { query, variables } });
  const [first] = data.errors ?? [];
  if (first) {
    const error = new GitHubError({
      method: "POST",
      path: "/graphql",
      status:
        GRAPHQL_ERROR_STATUS[first.type ?? ""] ?? GRAPHQL_UNTYPED_ERROR_STATUS,
      githubMessages: messagesOf(data, "GraphQL error"),
      graphqlPath: first.path?.join("."),
    });
    logger.warn(
      {
        path: "/graphql",
        graphqlType: first.type,
        graphqlPath: error.graphqlPath,
        githubMessages: error.githubMessages,
      },
      "GitHub GraphQL query returned errors"
    );
    throw error;
  }
  return data.data as T;
};

/**
 * `GET /app`, authenticated by the App JWT. Succeeds only when GitHub accepts
 * the JWT, and returns the app's slug, which names its `<slug>[bot]` user.
 */
export const getAuthenticatedApp = async (
  jwt: string
): Promise<{ slug: string | undefined }> => {
  const { data } = await githubRequest<{ slug?: string | null } | undefined>({
    method: "GET",
    path: "/app",
    token: jwt,
  });
  return { slug: data?.slug ?? undefined };
};

/** A GitHub account: its immutable id and its current login. */
export type Account = { id: number; login: string };

/**
 * `GET` on a public user endpoint: the account, or `undefined` on a 404.
 *
 * A 404 doesn't prove there's no such account: GitHub also hides some that
 * still exist, a spam-flagged account for one.
 */
const getAccount = async (
  token: string,
  path: string
): Promise<Account | undefined> => {
  try {
    const { data } = await githubRequest<Account>({
      method: "GET",
      path,
      token,
    });
    return { id: data.id, login: data.login };
  } catch (error) {
    if (error instanceof GitHubError && error.status === 404) return undefined;
    throw error;
  }
};

/** `GET /user/{account_id}`: the account with this id, whatever its login is now. */
export const getAccountById = (token: string, githubUserId: string) =>
  getAccount(token, `/user/${segment(githubUserId)}`);

/** `GET /users/{username}`: the account that has this login now. */
export const getAccountByLogin = (token: string, login: string) =>
  getAccount(token, `/users/${segment(login)}`);

/**
 * `GET /repos/{owner}/{repo}`: the repository's immutable id and its current
 * name, or `undefined` on a 404.
 *
 * GitHub answers a renamed repository's old name with a redirect to the
 * repository's id, which `fetch` follows, so the old name still finds it. A
 * 404 means there's no such repository, or the token can't see it.
 */
export const getRepository = async (
  token: string,
  org: string,
  repo: string
): Promise<{ id: number; name: string } | undefined> => {
  try {
    const { data } = await githubRequest<{ id: number; name: string }>({
      method: "GET",
      path: `/repos/${segment(org)}/${segment(repo)}`,
      token,
    });
    return { id: data.id, name: data.name };
  } catch (error) {
    if (error instanceof GitHubError && error.status === 404) return undefined;
    throw error;
  }
};

/** `GET /orgs/{org}/installation`, authenticated by the App JWT. */
export const getOrgInstallation = async (
  jwt: string,
  org: string
): Promise<Installation> => {
  const { data } = await githubRequest<{
    id: number;
    permissions: Permissions;
    repository_selection: "all" | "selected";
    suspended_at?: string | null;
  }>({ method: "GET", path: `/orgs/${segment(org)}/installation`, token: jwt });
  return {
    id: data.id,
    permissions: data.permissions,
    repositorySelection: data.repository_selection,
    suspended: Boolean(data.suspended_at),
  };
};

/** Exchanges the App JWT for an installation token scoped to the given repositories and permissions. */
export const createInstallationToken = async (
  jwt: string,
  installationId: number,
  scope: { repositories?: string[]; permissions: Permissions }
): Promise<string> => {
  const { data } = await githubRequest<{ token: string }>({
    method: "POST",
    path: `/app/installations/${installationId}/access_tokens`,
    token: jwt,
    body: scope,
  });
  return data.token;
};

export const listInstallationRepositories = async (
  token: string,
  page: number,
  perPage: number
): Promise<{ total: number; repositories: Repository[] }> => {
  const { data } = await githubRequest<{
    total_count: number;
    repositories: Repository[];
  }>({
    method: "GET",
    path: `/installation/repositories?${new URLSearchParams({
      per_page: String(perPage),
      page: String(page),
    }).toString()}`,
    token,
  });
  return { total: data.total_count, repositories: data.repositories };
};

/** The names of the org's custom repository roles. GitHub only has these on Enterprise Cloud. */
export const listCustomRepositoryRoles = async (
  token: string,
  org: string
): Promise<string[]> => {
  const { data } = await githubRequest<{ custom_roles?: { name: string }[] }>({
    method: "GET",
    path: `/orgs/${segment(org)}/custom-repository-roles`,
    token,
  });
  return (data.custom_roles ?? []).map(({ name }) => name);
};

/** The org's base repository permission, when GitHub shows it to this token. */
export const getOrgBasePermission = async (
  token: string,
  org: string
): Promise<string | undefined> => {
  const { data } = await githubRequest<{
    default_repository_permission?: string | null;
  }>({ method: "GET", path: `/orgs/${segment(org)}`, token });
  return data.default_repository_permission ?? undefined;
};

/** `GET /orgs/{org}/memberships/{username}`: the membership state, or `undefined` for a non-member. */
export const getOrgMembershipState = async (
  token: string,
  org: string,
  login: string
): Promise<string | undefined> => {
  try {
    const { data } = await githubRequest<{ state: string }>({
      method: "GET",
      path: `/orgs/${segment(org)}/memberships/${segment(login)}`,
      token,
    });
    return data.state;
  } catch (error) {
    if (error instanceof GitHubError && error.status === 404) return undefined;
    throw error;
  }
};

/**
 * `PUT /repos/{owner}/{repo}/collaborators/{username}`.
 *
 * 204 means the role was set. 201 means GitHub created an invitation instead,
 * whose id is returned so the caller can cancel it.
 */
export const putCollaborator = async (
  token: string,
  org: string,
  repo: string,
  login: string,
  permission: string
): Promise<{ invited: boolean; invitationId: number | undefined }> => {
  const { status, data } = await githubRequest<{ id?: number } | undefined>({
    method: "PUT",
    path: `/repos/${segment(org)}/${segment(repo)}/collaborators/${segment(login)}`,
    token,
    body: { permission },
  });
  const invited = status === 201;
  return { invited, invitationId: invited ? data?.id : undefined };
};

export const deleteCollaborator = async (
  token: string,
  org: string,
  repo: string,
  login: string
): Promise<void> => {
  await githubRequest({
    method: "DELETE",
    path: `/repos/${segment(org)}/${segment(repo)}/collaborators/${segment(login)}`,
    token,
  });
};

export type RepositoryInvitation = {
  id: number;
  invitee: { login: string } | null;
  /** Who sent it: an admin, or the app's `<slug>[bot]` user when the app's PUT created it. */
  inviter: { login: string } | null;
};

/** One page of `GET /repos/{owner}/{repo}/invitations`: the repo's pending invitations. */
export const listRepositoryInvitations = async (
  token: string,
  org: string,
  repo: string,
  page: number,
  perPage: number
): Promise<RepositoryInvitation[]> => {
  const { data } = await githubRequest<RepositoryInvitation[]>({
    method: "GET",
    path: `/repos/${segment(org)}/${segment(repo)}/invitations?${new URLSearchParams(
      { per_page: String(perPage), page: String(page) }
    ).toString()}`,
    token,
  });
  return data;
};

export const deleteInvitation = async (
  token: string,
  org: string,
  repo: string,
  invitationId: number
): Promise<void> => {
  await githubRequest({
    method: "DELETE",
    path: `/repos/${segment(org)}/${segment(repo)}/invitations/${invitationId}`,
    token,
  });
};
