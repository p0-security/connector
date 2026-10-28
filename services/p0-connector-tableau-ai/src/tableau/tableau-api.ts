import {
  ConnectorError,
  connectorErrorTypeForHttpStatus,
  createLogger,
} from "@p0security/connector";
import { createHmac, randomUUID } from "node:crypto";

const logger = createLogger();

const API_TIMEOUT = 10_000;
const API_VERSION = "3.26";
const PAGE_SIZE = 1000;
// Tableau refuses a connected-app JWT that lives longer than 10 minutes.
const JWT_LIFETIME_SECONDS = 5 * 60;

export type TableauSite = {
  /** Pod URL, e.g. "https://us-east-1.online.tableau.com" */
  server: string;
  contentUrl: string;
};

export type ConnectedApp = {
  clientId: string;
  secretId: string;
  secret: string;
};

export type TableauSession = {
  site: TableauSite;
  siteId: string;
  token: string;
};

type TableauRequest = {
  session: TableauSession;
  // Fetch uppercases only some method names, so pass them uppercase.
  method: "DELETE" | "GET" | "POST" | "PUT";
  path: string;
  body?: unknown;
};

type ErrorBody = { error?: { summary?: string; detail?: string } };

const errorMessage = async (response: Response) =>
  await response
    .json()
    .then((data) => {
      const error = (data as ErrorBody | undefined)?.error;
      return error
        ? [error.summary, error.detail].filter(Boolean).join(": ")
        : undefined;
    })
    .catch(() => undefined);

/**
 * Runs a Tableau REST call, converting any failure into a
 * {@link ConnectorError}. Only the HTTP status and Tableau's own message are
 * surfaced. The request, whose headers hold the session token, is never
 * attached to the error.
 *
 * @param path Path after `/api/<version>`
 * @returns The parsed JSON body, or `undefined` for an empty response
 */
const tableauFetch = async <T>(
  site: TableauSite,
  request: Omit<TableauRequest, "session"> & { token?: string }
): Promise<T> => {
  const { method, path, body, token } = request;

  let response: Response;
  try {
    response = await fetch(`${site.server}/api/${API_VERSION}${path}`, {
      method,
      headers: {
        Accept: "application/json",
        ...(token ? { "X-Tableau-Auth": token } : {}),
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(API_TIMEOUT),
    });
  } catch (error) {
    logger.error({ method, path, error }, "Tableau request failed");
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `Tableau ${method} ${path} failed: ${
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
      "Tableau request returned a non-2xx response"
    );
    throw new ConnectorError({
      type: connectorErrorTypeForHttpStatus(status),
      message: `Tableau ${method} ${path} failed (${status}): ${
        message ?? response.statusText
      }`,
      payload: { status },
    });
  }

  logger.debug(
    { method, path, status: response.status },
    "Tableau request succeeded"
  );
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
};

const tableauRequest = async <T>({ session, ...request }: TableauRequest) =>
  await tableauFetch<T>(session.site, { ...request, token: session.token });

const isStatus = (error: unknown, status: number) =>
  error instanceof ConnectorError &&
  (error.data.payload as { status?: number } | undefined)?.status === status;

/** Runs a delete, and treats an object that is already gone as deleted. */
const deleteIdempotently = async (request: TableauRequest) => {
  try {
    await tableauRequest<undefined>(request);
  } catch (error) {
    if (isStatus(error, 404)) return;
    throw error;
  }
};

const base64Url = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

/** Signs a direct-trust connected-app JWT that signs in as `sub`. */
const signJwt = (app: ConnectedApp, sub: string, scopes: string[]) => {
  const header = base64Url({
    alg: "HS256",
    typ: "JWT",
    kid: app.secretId,
    iss: app.clientId,
  });
  const payload = base64Url({
    iss: app.clientId,
    sub,
    aud: "tableau",
    exp: Math.floor(Date.now() / 1000) + JWT_LIFETIME_SECONDS,
    jti: randomUUID(),
    scp: scopes,
  });
  const signature = createHmac("sha256", app.secret)
    .update(`${header}.${payload}`)
    .digest("base64url");
  return `${header}.${payload}.${signature}`;
};

type SignInResponse = {
  credentials: { token: string; site: { id: string } };
};

/** Signs in to a site as `user` with a connected-app JWT limited to
 * `scopes`. */
export const signIn = async (
  site: TableauSite,
  app: ConnectedApp,
  user: string,
  scopes: string[]
): Promise<TableauSession> => {
  const { credentials } = await tableauFetch<SignInResponse>(site, {
    method: "POST",
    path: "/auth/signin",
    body: {
      credentials: {
        jwt: signJwt(app, user, scopes),
        site: { contentUrl: site.contentUrl },
      },
    },
  });
  return { site, siteId: credentials.site.id, token: credentials.token };
};

/** Ends a session. A failure is logged, not thrown, because the session ends
 * on its own. */
export const signOut = async (session: TableauSession) =>
  await tableauRequest<undefined>({
    session,
    method: "POST",
    path: "/auth/signout",
  }).catch((error: unknown) =>
    logger.warn({ error }, "failed to sign out of Tableau")
  );

const sitePath = (session: TableauSession, path: string) =>
  `/sites/${session.siteId}${path}`;

type Pagination = {
  pageNumber: string;
  pageSize: string;
  totalAvailable: string;
};

const listAll = async <T>(
  session: TableauSession,
  path: string,
  items: (body: unknown) => T[] | undefined
): Promise<T[]> => {
  const all: T[] = [];
  for (let page = 1; ; page++) {
    const separator = path.includes("?") ? "&" : "?";
    const body = await tableauRequest<{ pagination: Pagination }>({
      session,
      method: "GET",
      path: sitePath(
        session,
        `${path}${separator}pageSize=${PAGE_SIZE}&pageNumber=${page}`
      ),
    });
    all.push(...(items(body) ?? []));
    if (page * PAGE_SIZE >= Number(body.pagination.totalAvailable)) return all;
  }
};

export type Project = { id: string; name: string; contentPermissions: string };

/** Lists projects whose content permissions are locked to the project, so
 * that its default permissions apply to all of its content. */
export const listLockedProjects = async (
  session: TableauSession
): Promise<Project[]> => {
  const projects = await listAll<Project>(
    session,
    "/projects",
    (body) => (body as { projects?: { project?: Project[] } }).projects?.project
  );
  return projects.filter(({ contentPermissions }) =>
    contentPermissions.startsWith("LockedToProject")
  );
};

export type SiteRole = "ExplorerCanPublish" | "Unlicensed" | "Viewer";

type User = { id: string; name: string; siteRole: string };

/** Finds a user by exact name. */
export const findUser = async (
  session: TableauSession,
  name: string
): Promise<User | undefined> => {
  const users = await listAll<User>(
    session,
    `/users?filter=name:eq:${encodeURIComponent(name)}`,
    (body) => (body as { users?: { user?: User[] } }).users?.user
  );
  return users.find((user) => user.name === name);
};

/** Adds a user to the site. Tableau Cloud emails an invitation to it. */
export const createUser = async (
  session: TableauSession,
  name: string,
  siteRole: SiteRole
): Promise<User> => {
  const { user } = await tableauRequest<{ user: User }>({
    session,
    method: "POST",
    path: sitePath(session, "/users"),
    body: { user: { name, siteRole } },
  });
  return user;
};

export const setSiteRole = async (
  session: TableauSession,
  userId: string,
  siteRole: SiteRole
) =>
  await tableauRequest<unknown>({
    session,
    method: "PUT",
    path: sitePath(session, `/users/${userId}`),
    body: { user: { siteRole } },
  });

/** Removes a user from the site, which ends its open sessions. A user that
 * Tableau will not remove, because it owns content, gets the Unlicensed site
 * role instead, which also ends its sessions. */
export const removeUser = async (session: TableauSession, userId: string) => {
  try {
    await deleteIdempotently({
      session,
      method: "DELETE",
      path: sitePath(session, `/users/${userId}`),
    });
  } catch (error) {
    if (!isStatus(error, 409)) throw error;
    logger.warn({ userId }, "user owns content; setting it to Unlicensed");
    await setSiteRole(session, userId, "Unlicensed");
  }
};

/** A project's own permissions, or the default permissions it gives one kind
 * of content. */
export type PermissionTarget = "datasources" | "project" | "workbooks";

export type Capability = { name: string; mode: "Allow" | "Deny" };

type GranteeCapabilities = {
  user?: { id: string };
  group?: { id: string };
  capabilities: { capability: Capability[] };
};

const permissionsPath = (
  session: TableauSession,
  projectId: string,
  target: PermissionTarget
) =>
  sitePath(
    session,
    target === "project"
      ? `/projects/${projectId}/permissions`
      : `/projects/${projectId}/default-permissions/${target}`
  );

/** Reads the capabilities that a project gives one user directly. */
export const getUserCapabilities = async (
  session: TableauSession,
  projectId: string,
  target: PermissionTarget,
  userId: string
): Promise<Capability[]> => {
  const body = await tableauRequest<{
    permissions?: { granteeCapabilities?: GranteeCapabilities[] };
  }>({
    session,
    method: "GET",
    path: permissionsPath(session, projectId, target),
  });
  return (body.permissions?.granteeCapabilities ?? [])
    .filter((grantee) => grantee.user?.id === userId)
    .flatMap((grantee) => grantee.capabilities.capability);
};

export const addUserCapabilities = async (
  session: TableauSession,
  projectId: string,
  target: PermissionTarget,
  userId: string,
  capabilities: Capability[]
) =>
  await tableauRequest<unknown>({
    session,
    method: "PUT",
    path: permissionsPath(session, projectId, target),
    body: {
      permissions: {
        granteeCapabilities: [
          { user: { id: userId }, capabilities: { capability: capabilities } },
        ],
      },
    },
  });

export const removeUserCapability = async (
  session: TableauSession,
  projectId: string,
  target: PermissionTarget,
  userId: string,
  { name, mode }: Capability
) =>
  await deleteIdempotently({
    session,
    method: "DELETE",
    path: `${permissionsPath(session, projectId, target)}/users/${userId}/${name}/${mode}`,
  });
