import {
  ConnectorError,
  connectorErrorTypeForHttpStatus,
  createLogger,
} from "@p0security/connector-core";

const logger = createLogger();

const API_TIMEOUT = 10_000;

// Self-managed instances are not supported yet. A fixed host keeps a request
// context from sending the admin token anywhere else.
const API_BASE = "https://gitlab.com/api/v4";

const PAGE_SIZE = 100;

/** A GitLab access token, sent as `PRIVATE-TOKEN` */
export type GitlabAuth = { token: string };

export type GitlabProject = { id: number; pathWithNamespace: string };

export type GitlabToken = { id: number; token: string };

type GitlabRequest = {
  auth: GitlabAuth;
  method: "DELETE" | "GET" | "POST" | "PUT";
  path: string;
  query?: Record<string, string>;
  body?: Record<string, unknown>;
};

type ErrorBody = {
  message?: unknown;
  error?: string;
  error_description?: string;
};

/** GitLab's error text: `message` holds a string or an object of field
 * errors; OAuth errors use `error` and `error_description`. */
const errorMessage = async (response: Response) =>
  await response
    .json()
    .then((json) => {
      const data = json as ErrorBody | undefined;
      if (typeof data?.message === "string") return data.message;
      if (data?.message) return JSON.stringify(data.message);
      return data?.error_description ?? data?.error;
    })
    .catch(() => undefined);

/**
 * Runs a GitLab API call, converting any failure into a {@link ConnectorError}
 * so the framework renders it to the user. Only the HTTP status and GitLab's
 * own message are surfaced. The request, whose headers hold the token, is
 * never attached to the error.
 *
 * @returns The parsed JSON body (`undefined` for a 204 response), and the next
 * page number when the response is paginated and has one
 */
const gitlabRequest = async <T>(
  request: GitlabRequest
): Promise<{ data: T; nextPage?: string }> => {
  const { auth, method, path, query, body } = request;
  const url = `${API_BASE}${path}${query ? `?${new URLSearchParams(query).toString()}` : ""}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: {
        "PRIVATE-TOKEN": auth.token,
        Accept: "application/json",
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(API_TIMEOUT),
    });
  } catch (error) {
    logger.error({ method, path, error }, "GitLab request failed");
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `GitLab ${method} ${path} failed: ${
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
      "GitLab request returned a non-2xx response"
    );
    throw new ConnectorError({
      type: connectorErrorTypeForHttpStatus(status),
      message: `GitLab ${method} ${path} failed (${status}): ${
        message ?? response.statusText
      }`,
      payload: { status },
    });
  }

  logger.debug(
    { method, path, status: response.status },
    "GitLab request succeeded"
  );
  const nextPage = response.headers.get("x-next-page") || undefined;
  if (response.status === 204) return { data: undefined as T, nextPage };
  return { data: (await response.json()) as T, nextPage };
};

/** Reads every page of a list endpoint. */
const listAll = async <T>(
  request: Omit<GitlabRequest, "body" | "method">
): Promise<T[]> => {
  const items: T[] = [];
  let page: string | undefined = "1";
  while (page) {
    const { data, nextPage }: { data: T[]; nextPage?: string } =
      await gitlabRequest<T[]>({
        ...request,
        method: "GET",
        query: { ...request.query, per_page: String(PAGE_SIZE), page },
      });
    items.push(...data);
    page = nextPage;
  }
  return items;
};

const isNotFound = (error: unknown) =>
  error instanceof ConnectorError && error.data.type === "object_not_found";

/** Runs a delete, and treats an object that is already gone as deleted. */
const deleteIdempotently = async (request: GitlabRequest) => {
  try {
    await gitlabRequest<undefined>(request);
  } catch (error) {
    if (isNotFound(error)) return;
    throw error;
  }
};

const serviceAccountsPath = (groupId: string) =>
  `/groups/${encodeURIComponent(groupId)}/service_accounts`;

const tokensPath = (groupId: string, userId: number) =>
  `${serviceAccountsPath(groupId)}/${userId}/personal_access_tokens`;

/** Finds a service account of the group by its exact username. */
export const findServiceAccountId = async (
  auth: GitlabAuth,
  params: { groupId: string; username: string }
): Promise<number | undefined> => {
  const { groupId, username } = params;
  const { data } = await gitlabRequest<{ id: number }[]>({
    auth,
    method: "GET",
    path: "/users",
    query: { username },
  });
  const [user] = data;
  if (!user) return undefined;
  // A username is global on GitLab.com, so confirm the user is this group's
  // service account before the connector changes it.
  try {
    await gitlabRequest<unknown>({
      auth,
      method: "GET",
      path: `${serviceAccountsPath(groupId)}/${user.id}`,
    });
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
  return user.id;
};

export const createServiceAccount = async (
  auth: GitlabAuth,
  params: { groupId: string; username: string; name: string }
): Promise<number> => {
  const { groupId, username, name } = params;
  const { data } = await gitlabRequest<{ id: number }>({
    auth,
    method: "POST",
    path: serviceAccountsPath(groupId),
    body: { username, name },
  });
  return data.id;
};

/** Deletes a service account and, with it, its tokens and memberships. An
 * account that does not exist is not an error. GitLab removes the account in
 * the background, but refuses its tokens at once. */
export const deleteServiceAccount = async (
  auth: GitlabAuth,
  params: { groupId: string; userId: number }
) =>
  await deleteIdempotently({
    auth,
    method: "DELETE",
    path: `${serviceAccountsPath(params.groupId)}/${params.userId}`,
    query: { hard_delete: "true" },
  });

/** Creates a token for a service account. Without `expiresAt`, GitLab sets
 * the longest lifetime that it allows. */
export const createServiceAccountToken = async (
  auth: GitlabAuth,
  params: {
    groupId: string;
    userId: number;
    name: string;
    scopes: string[];
    expiresAt?: string;
  }
): Promise<GitlabToken> => {
  const { groupId, userId, name, scopes, expiresAt } = params;
  const { data } = await gitlabRequest<GitlabToken>({
    auth,
    method: "POST",
    path: tokensPath(groupId, userId),
    body: { name, scopes, ...(expiresAt ? { expires_at: expiresAt } : {}) },
  });
  return { id: data.id, token: data.token };
};

/** Finds the id of a service account's active token by its exact name.
 *
 * @throws {ConnectorError} when more than one active token has that name
 */
export const findServiceAccountTokenId = async (
  auth: GitlabAuth,
  params: { groupId: string; userId: number; name: string }
): Promise<number | undefined> => {
  const { groupId, userId, name } = params;
  const tokens = await listAll<{ id: number; name: string }>({
    auth,
    path: tokensPath(groupId, userId),
    query: { state: "active", search: name },
  });
  // The search is not an exact match, so compare names here.
  const matches = tokens.filter((token) => token.name === name);
  if (matches.length > 1) {
    throw new ConnectorError({
      type: "unknown",
      message: `More than one GitLab access token is named "${name}"`,
      payload: { count: matches.length },
    });
  }
  return matches[0]?.id;
};

/** Revokes a service account's token. A token that does not exist is not an
 * error. */
export const revokeServiceAccountToken = async (
  auth: GitlabAuth,
  params: { groupId: string; userId: number; tokenId: number }
) =>
  await deleteIdempotently({
    auth,
    method: "DELETE",
    path: `${tokensPath(params.groupId, params.userId)}/${params.tokenId}`,
  });

/** The projects of the group and its subgroups, without archived projects. */
export const listGroupProjects = async (
  auth: GitlabAuth,
  groupId: string
): Promise<GitlabProject[]> =>
  (
    await listAll<{ id: number; path_with_namespace: string }>({
      auth,
      path: `/groups/${encodeURIComponent(groupId)}/projects`,
      query: { include_subgroups: "true", simple: "true", archived: "false" },
    })
  ).map((project) => ({
    id: project.id,
    pathWithNamespace: project.path_with_namespace,
  }));

/** The projects that the token's own user is a member of. */
export const listMemberProjects = async (
  auth: GitlabAuth
): Promise<GitlabProject[]> =>
  (
    await listAll<{ id: number; path_with_namespace: string }>({
      auth,
      path: "/projects",
      query: { membership: "true", simple: "true" },
    })
  ).map((project) => ({
    id: project.id,
    pathWithNamespace: project.path_with_namespace,
  }));

export const getProject = async (
  auth: GitlabAuth,
  path: string
): Promise<GitlabProject> => {
  const { data } = await gitlabRequest<{
    id: number;
    path_with_namespace: string;
  }>({ auth, method: "GET", path: `/projects/${encodeURIComponent(path)}` });
  return { id: data.id, pathWithNamespace: data.path_with_namespace };
};

const membersPath = (projectId: number) => `/projects/${projectId}/members`;

/** Makes the user a direct member of the project with exactly
 * `accessLevel`. */
export const setProjectMember = async (
  auth: GitlabAuth,
  params: { projectId: number; userId: number; accessLevel: number }
) => {
  const { projectId, userId, accessLevel } = params;
  let current: number | undefined;
  try {
    const { data } = await gitlabRequest<{ access_level: number }>({
      auth,
      method: "GET",
      path: `${membersPath(projectId)}/${userId}`,
    });
    current = data.access_level;
  } catch (error) {
    if (!isNotFound(error)) throw error;
  }
  if (current === accessLevel) return;
  await gitlabRequest<unknown>(
    current === undefined
      ? {
          auth,
          method: "POST",
          path: membersPath(projectId),
          body: { user_id: userId, access_level: accessLevel },
        }
      : {
          auth,
          method: "PUT",
          path: `${membersPath(projectId)}/${userId}`,
          body: { access_level: accessLevel },
        }
  );
};

/** Removes the user from the project. A user that is not a member is not an
 * error. */
export const removeProjectMember = async (
  auth: GitlabAuth,
  params: { projectId: number; userId: number }
) =>
  await deleteIdempotently({
    auth,
    method: "DELETE",
    path: `${membersPath(params.projectId)}/${params.userId}`,
  });
