import {
  ConnectorError,
  type ConnectorErrorType,
  connectorErrorTypeForHttpStatus,
  createLogger,
} from "@p0security/connector";
import { z } from "zod";

const logger = createLogger();

const API_TIMEOUT = 10_000;

const API_PATH = "/api/4.0";

/** A Looker API key: the client ID and client secret of one Looker account.
 * The field names are Looker's, and the ones that the secrets store. */
export type LookerApiKey = {
  client_id: string;
  client_secret: string;
};

/** An access token for one Looker instance, from {@link login}. */
export type LookerSession = {
  /** The instance's URL, e.g. "https://example.looker.app" */
  baseUrl: string;
  accessToken: string;
};

type LookerRequest = {
  baseUrl: string;
  /** Absent for `/login` only */
  accessToken?: string;
  // Fetch uppercases only some method names, and not PATCH, so pass them
  // uppercase.
  method: "DELETE" | "GET" | "PATCH" | "POST" | "PUT";
  path: string;
  /** Sent as JSON */
  body?: unknown;
  /** Sent as a form, which is how `/login` takes the key */
  form?: Record<string, string>;
};

// Looker's error body. Any part of it that has another shape is left out.
const errorBody = z.object({
  message: z.string().nullish().catch(undefined),
  errors: z
    .array(
      z
        .object({
          field: z.string().nullish().catch(undefined),
          code: z.string().nullish().catch(undefined),
          message: z.string().nullish().catch(undefined),
        })
        .catch({})
    )
    .nullish()
    .catch(undefined),
});

/**
 * What Looker says about a failed call.
 *
 * @returns `message`: Looker's `message`, then the field and message of each
 *   validation error. `codes`: the code of each validation error.
 */
const parseErrorDetails = async (
  response: Response
): Promise<{ message: string | undefined; codes: string[] }> =>
  await response
    .json()
    .then((data: unknown) => {
      const parsed = errorBody.safeParse(data);
      if (!parsed.success) return { message: undefined, codes: [] };
      const { message, errors } = parsed.data;
      const details = (errors ?? []).map((error) =>
        [error.field, error.message].filter(Boolean).join(" ")
      );
      return {
        message: [message, ...details].filter(Boolean).join("; ") || undefined,
        codes: (errors ?? []).flatMap(({ code }) => (code ? [code] : [])),
      };
    })
    .catch(() => ({ message: undefined, codes: [] }));

/**
 * A call that Looker answered with an error status. It is the
 * {@link ConnectorError} that P0 sees, and also keeps what Looker said, for
 * the client to tell one refusal from another.
 */
class LookerResponseError extends ConnectorError {
  readonly status: number;
  /** The codes of Looker's validation errors, such as `already_exists` */
  readonly codes: string[];
  readonly lookerMessage: string | undefined;

  constructor(
    options: ConstructorParameters<typeof ConnectorError>[0],
    looker: { status: number; codes: string[]; message: string | undefined }
  ) {
    super(options);
    this.status = looker.status;
    this.codes = looker.codes;
    this.lookerMessage = looker.message;
  }
}

const QUOTA_MESSAGE = /quota|rate limit|limit exceeded/i;

/**
 * A 429 is Looker's rate limit. Looker does not document what it answers when
 * the instance's monthly API quota runs out (W34), so a 403 that names a quota
 * or a limit counts as one too, and not as a missing privilege.
 */
const errorTypeFor = (
  status: number,
  message: string | undefined
): ConnectorErrorType =>
  status === 403 && message !== undefined && QUOTA_MESSAGE.test(message)
    ? "rate_limited"
    : connectorErrorTypeForHttpStatus(status);

/**
 * Runs a Looker API call, converting any failure into a {@link ConnectorError}
 * so the framework renders it to the user. The error carries only the HTTP
 * status and Looker's own message. The request holds the Admin key or its
 * token, so this never logs it or attaches it to the error.
 *
 * It retries no failure, so that a call Looker refused for the API quota
 * doesn't spend more of it.
 *
 * @returns The JSON body, unchecked, or `undefined` for a 204 response. Use
 *   {@link lookerJson} for a body the caller reads.
 */
const lookerRequest = async (request: LookerRequest): Promise<unknown> => {
  const { baseUrl, accessToken, method, path, body, form } = request;
  const payload =
    form !== undefined
      ? {
          type: "application/x-www-form-urlencoded",
          content: new URLSearchParams(form).toString(),
        }
      : body !== undefined
        ? { type: "application/json", content: JSON.stringify(body) }
        : undefined;

  const response = await fetch(`${baseUrl}${API_PATH}${path}`, {
    method,
    headers: {
      Accept: "application/json",
      ...(accessToken !== undefined
        ? { Authorization: `token ${accessToken}` }
        : {}),
      ...(payload !== undefined ? { "Content-Type": payload.type } : {}),
    },
    body: payload?.content,
    // The key and its token go to the instance's own host only.
    redirect: "error",
    signal: AbortSignal.timeout(API_TIMEOUT),
  }).catch((error: unknown) => {
    logger.warn({ method, path, error }, "Looker request failed");
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `Looker ${method} ${path} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      payload: {},
    });
  });

  if (!response.ok) {
    const { status } = response;
    const { message, codes } = await parseErrorDetails(response);
    const type = errorTypeFor(status, message);
    logger.warn(
      { method, path, status, message },
      "Looker request returned a non-2xx response"
    );
    throw new LookerResponseError(
      {
        type,
        message: `${
          type === "rate_limited" ? "Looker API limit reached. " : ""
        }Looker ${method} ${path} failed (${status}): ${
          message ?? response.statusText
        }`,
        payload: { status },
      },
      { status, codes, message }
    );
  }

  logger.debug(
    { method, path, status: response.status },
    "Looker request succeeded"
  );
  if (response.status === 204) return undefined;
  try {
    return await response.json();
  } catch {
    // For example a web page, when the URL is not a Looker instance's.
    throw new ConnectorError({
      type: "unknown",
      message: `Looker ${method} ${path} returned a response that is not JSON (${response.status})`,
      payload: { status: response.status },
    });
  }
};

/**
 * Runs a Looker API call and checks its body's shape.
 *
 * A body of another shape fails the call. The error says which call, and
 * quotes nothing of the body, because some bodies hold a key.
 */
const lookerJson = async <T>(
  request: LookerRequest,
  schema: z.ZodType<T>
): Promise<T> => {
  const parsed = schema.safeParse(await lookerRequest(request));
  if (!parsed.success) {
    const { method, path } = request;
    logger.warn({ method, path }, "Looker returned an unexpected response");
    throw new ConnectorError({
      type: "unknown",
      message: `Looker ${method} ${path} returned a response the connector doesn't recognize`,
      payload: {},
    });
  }
  return parsed.data;
};

// Looker API 4.0 sends ids as strings. Older versions sent numbers.
const lookerId = z
  .union([z.string().min(1), z.number().int().nonnegative()])
  .transform(String);

const isNotFound = (error: unknown) =>
  error instanceof ConnectorError && error.data.type === "object_not_found";

/** Runs a delete, and treats an object that is already gone as deleted. */
const deleteIdempotently = async (request: LookerRequest) => {
  try {
    await lookerRequest(request);
  } catch (error) {
    if (isNotFound(error)) return;
    throw error;
  }
};

const toUserPath = (userId: string) => `/users/${encodeURIComponent(userId)}`;

/**
 * Exchanges a Looker API key for an access token (`login`).
 *
 * The key goes in the form body. Looker is retiring the query parameters.
 *
 * @throws {ConnectorError} `insufficient_privileges` when Looker does not
 *   accept the key
 */
export const login = async (
  baseUrl: string,
  key: LookerApiKey
): Promise<LookerSession> => {
  const token = await lookerJson(
    {
      baseUrl,
      method: "POST",
      path: "/login",
      form: { client_id: key.client_id, client_secret: key.client_secret },
    },
    z.object({ access_token: z.string().nullish() })
  ).catch((error: unknown) => {
    // The API spec gives `/login` a 404 and no 401 or 403, so a key that
    // Looker does not accept arrives as "not found".
    if (
      error instanceof ConnectorError &&
      (error.data.type === "object_not_found" ||
        error.data.type === "insufficient_privileges")
    ) {
      throw new ConnectorError({
        type: "insufficient_privileges",
        message: `Looker did not accept the Admin API key at ${baseUrl}. Check the instance URL, and the key in the Admin key secret.`,
        payload: { ...error.data.payload, reason: "admin_key_rejected" },
      });
    }
    throw error;
  });
  if (!token.access_token) {
    throw new ConnectorError({
      type: "unknown",
      message: "Looker returned no access token for the Admin API key",
      payload: {},
    });
  }
  return { baseUrl, accessToken: token.access_token };
};

/** Ends the session's access token (`logout`), which would otherwise stay
 * valid for about an hour. */
export const logout = async (session: LookerSession) => {
  await lookerRequest({ ...session, method: "DELETE", path: "/logout" });
};

/**
 * Creates a Looker service account (`create_service_account`). The account has
 * no roles and no API key yet.
 *
 * @returns The account's Looker user id
 */
export const createServiceAccount = async (
  session: LookerSession,
  name: string
): Promise<string> => {
  const { id } = await lookerJson(
    {
      ...session,
      method: "POST",
      path: "/users/service_accounts?fields=id",
      body: { service_account_name: name },
    },
    z.object({ id: lookerId.nullish() })
  );
  if (!id) {
    throw new ConnectorError({
      type: "unknown",
      message: "Looker returned a Looker service account without an id",
      payload: {},
    });
  }
  return id;
};

/** Sets a Looker user's first and last name (`update_user`). */
export const setUserName = async (
  session: LookerSession,
  userId: string,
  name: { firstName: string; lastName: string }
) => {
  await lookerRequest({
    ...session,
    method: "PATCH",
    path: `${toUserPath(userId)}?fields=id`,
    body: { first_name: name.firstName, last_name: name.lastName },
  });
};

/**
 * Creates a Looker API key for a Looker user
 * (`create_user_credentials_api3`).
 *
 * Looker returns the client secret here and never again (W3), so the caller
 * must store the key before anything else.
 */
export const createApiKey = async (
  session: LookerSession,
  userId: string
): Promise<LookerApiKey> => {
  const { client_id, client_secret } = await lookerJson(
    {
      ...session,
      method: "POST",
      path: `${toUserPath(userId)}/credentials_api3`,
    },
    z.object({
      client_id: z.string().nullish(),
      client_secret: z.string().nullish(),
    })
  );
  if (!client_id || !client_secret) {
    throw new ConnectorError({
      type: "unknown",
      message:
        "Looker returned an API key without its client ID or client secret",
      payload: {},
    });
  }
  return { client_id, client_secret };
};

const PAGE_SIZE = 100;

// Rows that two consecutive pages share, so that rows deleted between two
// reads don't make the search skip a row.
const PAGE_OVERLAP = 10;

const PAGE_STEP = PAGE_SIZE - PAGE_OVERLAP;

// Bounds a search, so that paging that never ends cannot spend the instance's
// API quota.
const MAX_PAGES = 50;

// The rows that MAX_PAGES pages reach.
const MAX_ROWS = (MAX_PAGES - 1) * PAGE_STEP + PAGE_SIZE;

/**
 * Reads every page of a Looker search.
 *
 * Pages are read by offset, so a row deleted between two reads, such as by
 * another revoke, shifts the later rows up a place. Each page starts
 * PAGE_OVERLAP rows before the end of the last one, and a row read twice is
 * kept once, so that up to PAGE_OVERLAP deletions between two reads skip no
 * row.
 *
 * @param what Names the rows, for a search that finds more than it reads
 */
const searchAll = async <T extends { id: string }>(
  session: LookerSession,
  search: {
    path: string;
    params: Record<string, string>;
    row: z.ZodType<T>;
    what: string;
  }
): Promise<T[]> => {
  const { path, params, row, what } = search;
  const page = z.array(row);
  const readFrom = async (
    pageNumber: number,
    seen: ReadonlySet<string>
  ): Promise<T[]> => {
    if (pageNumber >= MAX_PAGES) {
      throw new ConnectorError({
        type: "unknown",
        message: `The Looker instance has at least ${MAX_ROWS} ${what}, which is more than the connector searches`,
        payload: { limit: MAX_ROWS },
      });
    }
    const query = new URLSearchParams({
      ...params,
      // A fixed order, so that a row created during the search lands on the
      // last page.
      sorts: "id",
      limit: String(PAGE_SIZE),
      offset: String(pageNumber * PAGE_STEP),
    });
    const batch = await lookerJson(
      { ...session, method: "GET", path: `${path}?${query.toString()}` },
      page
    );
    const fresh = batch.filter(({ id }) => !seen.has(id));
    if (batch.length < PAGE_SIZE) return fresh;
    const nowSeen = new Set([...seen, ...fresh.map(({ id }) => id)]);
    return [...fresh, ...(await readFrom(pageNumber + 1, nowSeen))];
  };
  return await readFrom(0, new Set());
};

const DIGITS = /^\d+$/;

/** Orders Looker ids: numbers first, by value, then any other id, by text. */
const compareIds = (a: string, b: string) => {
  const [aIsNumber, bIsNumber] = [DIGITS.test(a), DIGITS.test(b)];
  if (aIsNumber && bIsNumber) {
    const difference = BigInt(a) - BigInt(b);
    // BigInt(0), not 0n: the P0 app typechecks this file for ES2017.
    return difference < BigInt(0) ? -1 : difference > BigInt(0) ? 1 : 0;
  }
  if (aIsNumber !== bIsNumber) return aIsNumber ? -1 : 1;
  return a < b ? -1 : a > b ? 1 : 0;
};

/**
 * Finds the object of one kind with exactly this name.
 *
 * Looker's name search ignores case, and reads `%` and `_` as wildcards, so
 * the names are compared here. Nothing says that Looker keeps names unique:
 * of several objects with the name, this returns the one with the lowest id,
 * so that grants that race to create an object settle on the same one.
 */
const findByName = async <T extends { id: string; name?: string | null }>(
  session: LookerSession,
  search: { path: string; name: string; fields: string; row: z.ZodType<T> }
): Promise<T | undefined> => {
  const { path, name, fields, row } = search;
  const rows = await searchAll(session, {
    path,
    params: { name, fields },
    row,
    what: `matches for the name ${name}`,
  });
  return rows
    .filter((found) => found.name === name)
    .sort((a, b) => compareIds(a.id, b.id))[0];
};

export type LookerServiceAccount = {
  id: string;
  /** Absent when the account has none */
  firstName: string | undefined;
};

/**
 * Lists the Looker service accounts with exactly this name (`search_users`).
 *
 * The search has no filter for a Looker service account's name, so this reads
 * every Looker service account, a page at a time.
 *
 * @returns The accounts, with their first names. Nothing says that Looker keeps
 *   the names unique, so there can be more than one.
 */
export const listServiceAccounts = async (
  session: LookerSession,
  name: string
): Promise<LookerServiceAccount[]> => {
  const accounts = await searchAll(session, {
    path: "/users/search",
    params: {
      is_service_account: "true",
      fields: "id,service_account_name,first_name",
    },
    row: z.object({
      id: lookerId,
      service_account_name: z.string().nullish(),
      first_name: z.string().nullish(),
    }),
    what: "Looker service accounts",
  });
  return accounts
    .filter((account) => account.service_account_name === name)
    .map(({ id, first_name }) => ({ id, firstName: first_name ?? undefined }));
};

/** The Looker user ids of {@link listServiceAccounts}. */
export const listServiceAccountIds = async (
  session: LookerSession,
  name: string
): Promise<string[]> =>
  (await listServiceAccounts(session, name)).map(({ id }) => id);

/** Deletes a Looker service account (`delete_service_account`), and its API
 * keys with it. An account that does not exist is not an error. */
export const deleteServiceAccount = async (
  session: LookerSession,
  userId: string
) =>
  await deleteIdempotently({
    ...session,
    method: "DELETE",
    path: `/users/service_accounts/${encodeURIComponent(userId)}`,
  });

// Looker's answer to a create whose name is taken is undocumented. Its
// validation errors carry a `code`, and `already_exists` is one of them.
const NAME_TAKEN_CODE = "already_exists";
const NAME_TAKEN_MESSAGE =
  /already (exists|been taken|in use|taken)|must be unique|not unique/i;

/** Whether Looker refused a create because the name is taken. */
const isNameTaken = (error: unknown) =>
  error instanceof LookerResponseError &&
  (error.status === 409 ||
    (error.status === 422 &&
      (error.codes.includes(NAME_TAKEN_CODE) ||
        NAME_TAKEN_MESSAGE.test(error.lookerMessage ?? ""))));

/**
 * Creates a named object.
 *
 * @throws {ConnectorError} `already_exists` when Looker refuses the name as
 *   taken, so that the caller can look for the object that has it. The
 *   framework maps a 409 and a 422 to `unknown`, which is why this is told
 *   apart here.
 */
const createNamed = async <T>(
  session: LookerSession,
  create: { path: string; kind: string; name: string; body: unknown },
  schema: z.ZodType<T>
): Promise<T> => {
  const { path, kind, name, body } = create;
  try {
    return await lookerJson({ ...session, method: "POST", path, body }, schema);
  } catch (error) {
    if (!isNameTaken(error)) throw error;
    throw new ConnectorError({
      type: "already_exists",
      message: `Looker already has a ${kind} named ${name}`,
      payload: { kind, name },
    });
  }
};

export type LookerPermissionSet = {
  id: string;
  name: string;
  permissions: string[];
};

export type LookerModelSet = { id: string; name: string; models: string[] };

export type LookerRole = {
  id: string;
  name: string;
  /** Absent when the role has none, or Looker leaves it out */
  permissionSetId: string | undefined;
  /** Absent when the role has none, or Looker leaves it out */
  modelSetId: string | undefined;
};

const permissionSet = z
  .object({
    id: lookerId,
    name: z.string().nullish(),
    permissions: z.array(z.string()).nullish(),
  })
  .transform(
    ({ id, name, permissions }): LookerPermissionSet => ({
      id,
      name: name ?? "",
      permissions: permissions ?? [],
    })
  );

const modelSet = z
  .object({
    id: lookerId,
    name: z.string().nullish(),
    models: z.array(z.string()).nullish(),
  })
  .transform(
    ({ id, name, models }): LookerModelSet => ({
      id,
      name: name ?? "",
      models: models ?? [],
    })
  );

const role = z
  .object({
    id: lookerId,
    name: z.string().nullish(),
    permission_set: z.object({ id: lookerId }).nullish(),
    model_set: z.object({ id: lookerId }).nullish(),
  })
  .transform(
    ({ id, name, permission_set, model_set }): LookerRole => ({
      id,
      name: name ?? "",
      permissionSetId: permission_set?.id,
      modelSetId: model_set?.id,
    })
  );

/**
 * Every permission the instance knows, with the permission it depends on
 * (`all_permissions`).
 */
export const listPermissionParents = async (
  session: LookerSession
): Promise<Map<string, string | null>> => {
  const permissions = await lookerJson(
    { ...session, method: "GET", path: "/permissions" },
    z.array(
      z.object({
        permission: z.string().nullish(),
        parent: z.string().nullish(),
      })
    )
  );
  return new Map(
    permissions.flatMap(({ permission, parent }) =>
      permission ? [[permission, parent || null] as const] : []
    )
  );
};

/** The permission set with exactly this name (`search_permission_sets`). */
export const findPermissionSet = (session: LookerSession, name: string) =>
  findByName(session, {
    path: "/permission_sets/search",
    name,
    fields: "id,name,permissions",
    row: permissionSet,
  });

/** Creates a permission set (`create_permission_set`). */
export const createPermissionSet = (
  session: LookerSession,
  set: { name: string; permissions: string[] }
) =>
  createNamed(
    session,
    {
      path: "/permission_sets",
      kind: "permission set",
      name: set.name,
      body: set,
    },
    permissionSet
  );

/** The model set with exactly this name (`search_model_sets`). */
export const findModelSet = (session: LookerSession, name: string) =>
  findByName(session, {
    path: "/model_sets/search",
    name,
    fields: "id,name,models",
    row: modelSet,
  });

/** Creates a model set (`create_model_set`). */
export const createModelSet = (
  session: LookerSession,
  set: { name: string; models: string[] }
) =>
  createNamed(
    session,
    { path: "/model_sets", kind: "model set", name: set.name, body: set },
    modelSet
  );

/** The role with exactly this name (`search_roles`), with the ids of its
 * permission set and its model set. */
export const findRole = (session: LookerSession, name: string) =>
  findByName(session, {
    path: "/roles/search",
    name,
    fields: "id,name,permission_set,model_set",
    row: role,
  });

/** Creates a role from a permission set and a model set (`create_role`). */
export const createRole = (
  session: LookerSession,
  newRole: { name: string; permissionSetId: string; modelSetId: string }
) =>
  createNamed(
    session,
    {
      path: "/roles",
      kind: "role",
      name: newRole.name,
      body: {
        name: newRole.name,
        permission_set_id: newRole.permissionSetId,
        model_set_id: newRole.modelSetId,
      },
    },
    role
  );

/** Replaces the roles given to a user directly (`set_user_roles`). Roles that
 * the user gets from its groups stay (W2). */
export const setUserRoles = async (
  session: LookerSession,
  userId: string,
  roleIds: string[]
) => {
  await lookerRequest({
    ...session,
    method: "PUT",
    path: `${toUserPath(userId)}/roles?fields=id`,
    body: roleIds,
  });
};

/** The ids of the roles given to a user directly, without those from its
 * groups (`user_roles`). */
export const listDirectRoleIds = async (
  session: LookerSession,
  userId: string
): Promise<string[]> => {
  const query = new URLSearchParams({
    direct_association_only: "true",
    fields: "id",
  });
  const roles = await lookerJson(
    {
      ...session,
      method: "GET",
      path: `${toUserPath(userId)}/roles?${query.toString()}`,
    },
    z.array(z.object({ id: lookerId }))
  );
  return roles.map(({ id }) => id);
};

/**
 * The instance's models that an agent can use (`all_lookml_models`), with
 * their labels: those with at least one Explore, that aren't hidden. The MCP
 * server hides hidden models too, so a grant on one would show the agent
 * nothing.
 */
export const listModels = async (
  session: LookerSession
): Promise<{ name: string; label: string }[]> => {
  const query = new URLSearchParams({
    fields: "name,label",
    exclude_empty: "true",
    exclude_hidden: "true",
  });
  const models = await lookerJson(
    { ...session, method: "GET", path: `/lookml_models?${query.toString()}` },
    z.array(
      z.object({ name: z.string().nullish(), label: z.string().nullish() })
    )
  );
  return models.flatMap(({ name, label }) =>
    name ? [{ name, label: label || name }] : []
  );
};

/**
 * Finds a folder (`folder`).
 *
 * @returns The id of the folder's content metadata, which holds its access
 *   records, or `undefined` when there is no such folder
 */
export const findFolder = async (
  session: LookerSession,
  folderId: string
): Promise<{ contentMetadataId: string } | undefined> => {
  try {
    const { content_metadata_id } = await lookerJson(
      {
        ...session,
        method: "GET",
        path: `/folders/${encodeURIComponent(folderId)}?fields=id,content_metadata_id`,
      },
      z.object({ content_metadata_id: lookerId })
    );
    return { contentMetadataId: content_metadata_id };
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
};

export type LookerContentAccess = {
  id: string;
  /** Absent for a group's access */
  userId: string | undefined;
  permissionType: string;
};

/** The access records of a folder (`all_content_metadata_accesses`). */
export const listContentAccess = async (
  session: LookerSession,
  contentMetadataId: string
): Promise<LookerContentAccess[]> => {
  const query = new URLSearchParams({
    content_metadata_id: contentMetadataId,
    fields: "id,user_id,permission_type",
  });
  const accesses = await lookerJson(
    {
      ...session,
      method: "GET",
      path: `/content_metadata_access?${query.toString()}`,
    },
    z.array(
      z.object({
        id: lookerId,
        user_id: lookerId.nullish(),
        permission_type: z.string().nullish(),
      })
    )
  );
  return accesses.map(({ id, user_id, permission_type }) => ({
    id,
    userId: user_id ?? undefined,
    permissionType: permission_type ?? "",
  }));
};

/** Gives a user access to a folder (`create_content_metadata_access`). */
export const createContentAccess = async (
  session: LookerSession,
  access: {
    contentMetadataId: string;
    userId: string;
    permissionType: "edit" | "view";
  }
) => {
  await lookerRequest({
    ...session,
    method: "POST",
    path: "/content_metadata_access",
    body: {
      content_metadata_id: access.contentMetadataId,
      user_id: access.userId,
      permission_type: access.permissionType,
    },
  });
};

/** Changes the level of an access record
 * (`update_content_metadata_access`). */
export const updateContentAccess = async (
  session: LookerSession,
  accessId: string,
  permissionType: "edit" | "view"
) => {
  await lookerRequest({
    ...session,
    method: "PUT",
    path: `/content_metadata_access/${encodeURIComponent(accessId)}`,
    body: { permission_type: permissionType },
  });
};

/** Removes an access record (`delete_content_metadata_access`). A record that
 * does not exist is not an error. */
export const deleteContentAccess = async (
  session: LookerSession,
  accessId: string
) =>
  await deleteIdempotently({
    ...session,
    method: "DELETE",
    path: `/content_metadata_access/${encodeURIComponent(accessId)}`,
  });

export type LookerGroup = {
  id: string;
  name: string;
  /** New users join the group when they are created */
  includeByDefault: boolean;
  /** The names of the group's roles */
  roles: string[];
};

/** Every group, with its roles (`search_groups_with_roles`). */
export const listGroupsWithRoles = async (
  session: LookerSession
): Promise<LookerGroup[]> => {
  const groups = await searchAll(session, {
    path: "/groups/search/with_roles",
    params: { fields: "id,name,include_by_default,roles" },
    row: z.object({
      id: lookerId,
      name: z.string().nullish(),
      include_by_default: z.boolean().nullish(),
      roles: z.array(z.object({ name: z.string().nullish() })).nullish(),
    }),
    what: "groups",
  });
  return groups.map((group) => ({
    id: group.id,
    name: group.name ?? "",
    includeByDefault: group.include_by_default === true,
    roles: (group.roles ?? []).flatMap(({ name }) => (name ? [name] : [])),
  }));
};
