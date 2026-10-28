import { ConnectorError, type Logger } from "@p0security/connector";
import { z } from "zod";

import type { Site } from "../install/definition.ts";
import {
  callAtlassian,
  isTransient,
  requestDeadline,
} from "./atlassian-call.ts";
import { errorTypeForStatus, forgetAdminToken, getAdminToken } from "./auth.ts";

/**
 * A site's REST API, called with an admin access token. Every call through
 * one client shares its connector request's `deadline`.
 */
export type JiraClient = {
  cloudId: string;
  token: string;
  deadline: number;
  logger: Logger;
};

// No PUT: a PUT on a project role's actors replaces every member.
type JiraRequest = (
  | {
      method: "POST";
      /**
       * Whether sending the POST again is safe, so a failed one may be
       * retried. Each POST says why.
       */
      repeatable: boolean;
    }
  | { method: "DELETE" | "GET" }
) & {
  /** The path under `/rest/api/3`, with every variable segment encoded. */
  path: string;
  query?: Record<string, string>;
  body?: unknown;
  /** What the call does, for messages. The path is never quoted. */
  operation: string;
  /**
   * Whether Jira's own error text may go into the message. Off for a call
   * whose input P0 shouldn't see echoed, such as an email search.
   */
  quoteJira?: boolean;
};

export const apiBase = (cloudId: string) =>
  `https://api.atlassian.com/ex/jira/${encodeURIComponent(cloudId)}/rest/api/3`;

const jiraErrorBody = z.object({
  errorMessages: z.array(z.string()).optional(),
  errors: z.record(z.string(), z.string()).optional(),
});

/** Jira's error text: `errorMessages`, then the per-field `errors`. */
const jiraErrorText = async (response: Response) => {
  const parsed = jiraErrorBody.safeParse(
    await response.json().catch(() => undefined)
  );
  if (!parsed.success) return undefined;
  const { errorMessages = [], errors = {} } = parsed.data;
  const text = [...errorMessages, ...Object.values(errors)].join("; ");
  return text.length > 0 ? text : undefined;
};

/**
 * Runs one Jira REST call on the site's fixed API host, retried as
 * {@link callAtlassian} does, and turns any failure into a
 * {@link ConnectorError}. A GET or DELETE is always retried, a POST only when
 * it is repeatable. The token goes into the request's header only. Neither it
 * nor the path is put into an error or a log line.
 *
 * @returns The parsed JSON body, or `undefined` for a 204
 */
const jiraRequest = async (
  { cloudId, token, deadline, logger }: JiraClient,
  request: JiraRequest
): Promise<unknown> => {
  const { method, path, query, body, operation, quoteJira = true } = request;
  const search = query ? `?${new URLSearchParams(query).toString()}` : "";
  const response = await callAtlassian({
    url: `${apiBase(cloudId)}${path}${search}`,
    init: {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    },
    repeatable: request.method === "POST" ? request.repeatable : true,
    operation,
    deadline,
    logger,
  }).catch((error: unknown) => {
    logger.warn(
      {
        method,
        operation,
        error: error instanceof Error ? error.name : "unknown",
      },
      "the Jira request failed"
    );
    // The request's budget ran out, and the error says so.
    if (error instanceof ConnectorError) throw error;
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `The connector couldn't reach Jira to ${operation}. Try again.`,
      payload: { cloudId },
    });
  });

  if (!response.ok) {
    const { status } = response;
    const text = quoteJira ? await jiraErrorText(response) : undefined;
    logger.warn({ method, operation, status }, "Jira refused the request");
    throw new ConnectorError({
      type: errorTypeForStatus(status),
      message: `Jira failed to ${operation} (${status})${text === undefined ? "" : `: ${text}`}.${isTransient(status) ? " Try the request again in a few minutes." : ""}`,
      payload: { cloudId, status },
    });
  }

  if (response.status === 204) return undefined;
  return await response.json().catch(() => undefined);
};

/**
 * Jira's answer, parsed with `schema`. An answer of another shape fails as
 * `unknown`, without quoting it.
 */
const parseAnswer = <T>(
  schema: z.ZodType<T>,
  answer: unknown,
  { cloudId, logger }: JiraClient,
  operation: string
): T => {
  const parsed = schema.safeParse(answer);
  if (parsed.success) return parsed.data;
  logger.warn({ operation }, "Jira answered with an unexpected shape");
  throw new ConnectorError({
    type: "unknown",
    message: `Jira answered the call to ${operation} with a response the connector doesn't understand. Contact support@p0.dev.`,
    payload: { cloudId },
  });
};

const statusOf = (error: unknown) =>
  error instanceof ConnectorError ? error.data.payload.status : undefined;

/**
 * Runs `use` with a client for the site, signed in as its admin service
 * account. Each connector request calls it once, so the sign-in and every
 * Jira call share one deadline (see {@link requestDeadline}). When Jira
 * refuses the token (401), it drops the cached token, so the next call signs
 * in again.
 */
export const withJira = async <T>(
  site: Site,
  logger: Logger,
  use: (jira: JiraClient) => Promise<T>
): Promise<T> => {
  const deadline = requestDeadline();
  const token = await getAdminToken(site, logger, deadline);
  try {
    return await use({ cloudId: site.cloudId, token, deadline, logger });
  } catch (error) {
    if (statusOf(error) === 401) forgetAdminToken(site);
    throw error;
  }
};

const userSearchResult = z.array(
  z.object({ accountId: z.string(), emailAddress: z.string().optional() })
);

/**
 * The id of the one account whose email is `email`.
 *
 * Jira's search matches on a prefix of the name and the email, so the filter
 * drops an account that shows a different email. It keeps one that hides its
 * email, as a service account does: Jira Cloud returns its `emailAddress` as
 * an empty string.
 *
 * @throws {ConnectorError} `object_not_found`, unless exactly one account
 * matches
 */
export const fetchAccountIdByEmail = async (
  jira: JiraClient,
  email: string
): Promise<string> => {
  const operation = "search for the account";
  const found = parseAnswer(
    userSearchResult,
    await jiraRequest(jira, {
      method: "GET",
      path: "/user/search",
      query: { query: email },
      operation,
      quoteJira: false,
    }),
    jira,
    operation
  );
  const matches = found.filter(
    ({ emailAddress }) =>
      !emailAddress || emailAddress.toLowerCase() === email.toLowerCase()
  );
  const [match] = matches;
  if (matches.length !== 1 || match === undefined) {
    throw new ConnectorError({
      type: "object_not_found",
      message:
        matches.length === 0
          ? "No Jira account on the site has that email, or the admin account can't see it."
          : `${matches.length} Jira accounts on the site match that email. Enter the email of exactly one account.`,
      payload: { query: email, matches: matches.length },
    });
  }
  return match.accountId;
};

const myPermissionsResult = z.object({
  permissions: z.object({
    ADMINISTER: z.object({ havePermission: z.boolean() }).optional(),
  }),
});

/**
 * Whether the signed-in account holds the Administer Jira global permission.
 * A missing `ADMINISTER` entry counts as no.
 */
export const hasJiraAdmin = async (jira: JiraClient): Promise<boolean> => {
  const operation = "read the admin account's permissions";
  const { permissions } = parseAnswer(
    myPermissionsResult,
    await jiraRequest(jira, {
      method: "GET",
      path: "/mypermissions",
      query: { permissions: "ADMINISTER" },
      operation,
    }),
    jira,
    operation
  );
  return permissions.ADMINISTER?.havePermission === true;
};

const projectPath = (projectKey: string) =>
  `/project/${encodeURIComponent(projectKey)}`;

/**
 * Lets a "not found" from a project role endpoint count as gone. Every role
 * endpoint admits a holder of Administer Jira, so for one the project or
 * role is gone. Without it, Jira hides projects the same way, so P0 can't
 * tell.
 *
 * @throws ConnectorError (`insufficient_privileges`) when the admin account
 * no longer holds Administer Jira
 */
export const confirmGone = async (jira: JiraClient, projectKey: string) => {
  if (await hasJiraAdmin(jira)) return;
  throw new ConnectorError({
    type: "insufficient_privileges",
    message: `Jira says project ${projectKey} or its role doesn't exist, but the site's admin account no longer holds the Administer Jira global permission, so P0 can't tell whether the project is gone. Give the account Jira admin permissions again, then retry.`,
    payload: { projectKey },
  });
};

const rolePath = (projectKey: string, roleId: string) =>
  `${projectPath(projectKey)}/role/${encodeURIComponent(roleId)}`;

const projectResult = z.object({ id: z.string(), style: z.string() });

/** A project's id and style: `classic` is company-managed, `next-gen` team-managed. */
export const fetchProject = async (jira: JiraClient, projectKey: string) => {
  const operation = `read project ${projectKey}`;
  return parseAnswer(
    projectResult,
    await jiraRequest(jira, {
      method: "GET",
      path: projectPath(projectKey),
      operation,
    }),
    jira,
    operation
  );
};

const ROLE_ID = /\/role\/(\d+)$/;

/**
 * The project's role ids, by role name. Jira answers with each role's URL,
 * which ends in its id. A `Map`, so a role name such as `constructor` can't
 * match an object's own properties.
 */
export const fetchProjectRoleIds = async (
  jira: JiraClient,
  projectKey: string
): Promise<Map<string, string>> => {
  const operation = `list the roles of project ${projectKey}`;
  const roles = parseAnswer(
    z.record(z.string(), z.string()),
    await jiraRequest(jira, {
      method: "GET",
      path: `${projectPath(projectKey)}/role`,
      operation,
    }),
    jira,
    operation
  );
  return new Map(
    Object.entries(roles).flatMap(([name, url]) => {
      const id = ROLE_ID.exec(url)?.[1];
      return id === undefined ? [] : [[name, id] as const];
    })
  );
};

// Jira answers role, scheme and grant ids as numbers.
const numericId = z.union([z.number(), z.string()]).transform(String);

const siteRole = z.object({
  id: numericId,
  name: z.string(),
  description: z.string().optional(),
});

/** A site-wide project role, as P0 refers to it. */
export type SiteRole = z.infer<typeof siteRole>;

/** The site's project roles, the ones every company-managed project has. */
export const fetchSiteRoles = async (jira: JiraClient): Promise<SiteRole[]> => {
  const operation = "list the site's project roles";
  return parseAnswer(
    z.array(siteRole),
    await jiraRequest(jira, { method: "GET", path: "/role", operation }),
    jira,
    operation
  );
};

/**
 * The site role named `name`, created with `description` when the site has
 * none. A create that Jira refuses because a parallel call just made the role
 * counts once the role shows up by name, with whatever description it has.
 * `siteRoles`, when given, is a list the caller already fetched, so the first
 * lookup needs no request.
 */
export const findOrCreateSiteRole = async (
  jira: JiraClient,
  name: string,
  description: string,
  siteRoles?: readonly SiteRole[]
): Promise<SiteRole> => {
  const named = (roles: readonly SiteRole[]) =>
    roles.find((role) => role.name === name);
  const byName = async () => named(await fetchSiteRoles(jira));
  const existing = siteRoles === undefined ? await byName() : named(siteRoles);
  if (existing !== undefined) return existing;
  const operation = `create the project role "${name}"`;
  try {
    return parseAnswer(
      siteRole,
      await jiraRequest(jira, {
        method: "POST",
        path: "/role",
        body: { name, description },
        operation,
        // A repeat that finds the role made fails with 400 or 409, and the
        // lookup below then finds it.
        repeatable: true,
      }),
      jira,
      operation
    );
  } catch (error) {
    const status = statusOf(error);
    if (status === 400 || status === 409) {
      const raced = await byName();
      if (raced !== undefined) return raced;
    }
    throw error;
  }
};

const permissionSchemeResult = z.object({ id: numericId });

const permissionGrant = z.object({
  holder: z
    .object({
      type: z.string(),
      parameter: z.string().optional(),
      value: z.string().optional(),
    })
    .optional(),
  permission: z.string(),
});

type PermissionGrant = z.infer<typeof permissionGrant>;

const permissionGrants = z.object({ permissions: z.array(permissionGrant) });

/** The permissions a scheme grants the project role `roleId`. */
const fetchRoleGrants = async (
  jira: JiraClient,
  schemeId: string,
  roleId: string
): Promise<Set<string>> => {
  const operation = `list the grants of permission scheme ${schemeId}`;
  const { permissions: grants } = parseAnswer(
    permissionGrants,
    await jiraRequest(jira, {
      method: "GET",
      path: `/permissionscheme/${encodeURIComponent(schemeId)}/permission`,
      operation,
    }),
    jira,
    operation
  );
  const isRoleGrant = ({ holder }: PermissionGrant) =>
    holder?.type === "projectRole" &&
    (holder.value === roleId || holder.parameter === roleId);
  return new Set(
    grants.filter(isRoleGrant).map(({ permission }) => permission)
  );
};

/**
 * Makes sure the project's permission scheme grants the role each of
 * `permissions`, adding only the grants it lacks. Grants are never removed:
 * the scheme may be shared by other projects, and a grant to a role gives
 * nothing to anyone outside it.
 *
 * Jira refuses a grant that is already there with a 400, as after a retry or
 * a parallel grant. That counts as done once the scheme shows the grant.
 *
 * @returns How many grants it added
 */
export const ensureSchemeGrants = async (
  jira: JiraClient,
  projectKey: string,
  roleId: string,
  permissions: readonly string[]
): Promise<number> => {
  const schemeOperation = `read the permission scheme of project ${projectKey}`;
  const { id: schemeId } = parseAnswer(
    permissionSchemeResult,
    await jiraRequest(jira, {
      method: "GET",
      path: `${projectPath(projectKey)}/permissionscheme`,
      operation: schemeOperation,
    }),
    jira,
    schemeOperation
  );
  const held = await fetchRoleGrants(jira, schemeId, roleId);
  const missing = permissions.filter((permission) => !held.has(permission));
  for (const permission of missing) {
    try {
      await jiraRequest(jira, {
        method: "POST",
        path: `/permissionscheme/${encodeURIComponent(schemeId)}/permission`,
        body: { holder: { type: "projectRole", value: roleId }, permission },
        operation: `grant ${permission} to role ${roleId} in the permission scheme of project ${projectKey}`,
        // A repeat of a grant that landed fails with 400, handled below.
        repeatable: true,
      });
    } catch (error) {
      // When the scheme can't be read back, Jira's refusal stands.
      const granted =
        statusOf(error) === 400 &&
        (await fetchRoleGrants(jira, schemeId, roleId).then(
          (grants) => grants.has(permission),
          () => false
        ));
      if (granted) continue;
      throw error;
    }
  }
  return missing.length;
};

const roleResult = z.object({
  actors: z
    .array(
      z.object({ actorUser: z.object({ accountId: z.string() }).optional() })
    )
    .default([]),
});

/** The account ids that hold a project role directly. */
export const fetchRoleActorIds = async (
  jira: JiraClient,
  projectKey: string,
  roleId: string
): Promise<string[]> => {
  const operation = `read role ${roleId} of project ${projectKey}`;
  const { actors } = parseAnswer(
    roleResult,
    await jiraRequest(jira, {
      method: "GET",
      path: rolePath(projectKey, roleId),
      operation,
    }),
    jira,
    operation
  );
  return actors.flatMap(({ actorUser }) =>
    actorUser === undefined ? [] : [actorUser.accountId]
  );
};

/**
 * Whether a refused add or remove left the account where the call wanted it,
 * since Jira may refuse to add an existing member or to remove a missing one.
 * When the role can't be read, the answer is no, so the caller reports
 * Jira's first refusal.
 */
const settled = async (
  jira: JiraClient,
  projectKey: string,
  roleId: string,
  accountId: string,
  wantMember: boolean
) =>
  await fetchRoleActorIds(jira, projectKey, roleId).then(
    (ids) => ids.includes(accountId) === wantMember,
    () => false
  );

/**
 * Adds an account to a project role (POST, never PUT). Adding an account that
 * already holds the role succeeds.
 */
export const addRoleActor = async (
  jira: JiraClient,
  projectKey: string,
  roleId: string,
  accountId: string
) => {
  try {
    await jiraRequest(jira, {
      method: "POST",
      path: rolePath(projectKey, roleId),
      body: { user: [accountId] },
      operation: `add the account to role ${roleId} of project ${projectKey}`,
      // Adding a member again changes nothing, and a refusal of it is
      // checked below.
      repeatable: true,
    });
  } catch (error) {
    if (
      statusOf(error) === 400 &&
      (await settled(jira, projectKey, roleId, accountId, true))
    )
      return;
    throw error;
  }
};

/**
 * Removes an account from a project role. Removing an account that doesn't
 * hold it, or from a project or role that is gone, succeeds.
 */
export const removeRoleActor = async (
  jira: JiraClient,
  projectKey: string,
  roleId: string,
  accountId: string
) => {
  try {
    await jiraRequest(jira, {
      method: "DELETE",
      path: rolePath(projectKey, roleId),
      query: { user: accountId },
      operation: `remove the account from role ${roleId} of project ${projectKey}`,
    });
  } catch (error) {
    const status = statusOf(error);
    if (status === 404) {
      await confirmGone(jira, projectKey);
      return;
    }
    if (
      status === 400 &&
      (await settled(jira, projectKey, roleId, accountId, false))
    )
      return;
    throw error;
  }
};
