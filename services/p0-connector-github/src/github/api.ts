import { ConnectorError, createLogger } from "@p0security/connector-core";
import { z } from "zod";

const logger = createLogger();

const GITHUB_API_BASE = "https://api.github.com";
/** The pinned `X-GitHub-Api-Version`. Bump it deliberately. @see https://docs.github.com/en/rest/about-the-rest-api/api-versions */
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
  /** The id of the org the app is installed on, which GitHub's by-id team routes take. */
  orgId: number;
};

const repositorySchema = z.object({ name: z.string(), full_name: z.string() });

export type Repository = z.infer<typeof repositorySchema>;

type Method = "DELETE" | "GET" | "PATCH" | "POST" | "PUT";

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

type GitHubRequest<T> = {
  method: Method;
  path: string;
  /** A signed App JWT or an installation token. Each endpoint says which. */
  token: string;
  body?: unknown;
  /** The shape of a successful response's body. */
  schema: z.ZodType<T>;
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

/** Whether a GitHub call failed with a 404. */
export const isNotFound = (error: unknown): error is GitHubError =>
  error instanceof GitHubError && error.status === 404;

const githubRequest = async <T>(
  request: GitHubRequest<T>
): Promise<GitHubResponse<T>> => {
  const { method, path, token, body, schema } = request;
  const response = await fetch(`${GITHUB_API_BASE}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": GITHUB_API_VERSION,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(API_TIMEOUT),
  }).catch((error: unknown) => {
    // Network failure, timeout/abort, DNS error: there is no HTTP response.
    logger.warn({ method, path, error }, "GitHub request failed");
    throw new GitHubError({
      method,
      path,
      status: undefined,
      githubMessages: [error instanceof Error ? error.message : String(error)],
    });
  });

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
  return {
    status: response.status,
    data: parseResponse({ schema, data, method, path }),
  };
};

/**
 * Reads a response body with `schema`, or fails as `unknown`: GitHub answered
 * in a shape the connector doesn't know, which nobody can fix.
 */
const parseResponse = <T>(params: {
  schema: z.ZodType<T>;
  data: unknown;
  method: Method;
  path: string;
}): T => {
  const { schema, data, method, path } = params;
  const parsed = schema.safeParse(data);
  if (parsed.success) return parsed.data;
  logger.warn(
    {
      method,
      path,
      // Where each issue is and its code, never a value: one body is a token.
      issues: parsed.error.issues.map((issue) => ({
        path: issue.path.join("."),
        code: issue.code,
      })),
    },
    "GitHub returned a response the connector can't read"
  );
  throw new ConnectorError({
    type: "unknown",
    message: "GitHub answered in a shape the connector doesn't recognize.",
    payload: { method },
  });
};

/**
 * One URL path segment.
 *
 * `encodeURIComponent` leaves `.` and `..` alone, and `fetch` would resolve
 * them, so `login: ".."` would turn `/repos/o/r/collaborators/..` into
 * `/repos/o/r/`. The input schemas already refuse them, and this refuses
 * them again at the point where it matters.
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

// The envelope only. `data` is read with the query's own schema once there are
// no errors, since a failed query's partial data needn't match it.
const graphqlEnvelope = z.object({
  data: z.unknown().optional(),
  errors: z
    .array(
      z.object({
        type: z.string().nullish(),
        message: z.string().nullish(),
        path: z.array(z.union([z.string(), z.number()])).nullish(),
      })
    )
    .optional(),
});

/** Runs a GraphQL query, reading its data with `schema`. Any error in the response throws, even alongside partial data. */
export const githubGraphql = async <T>(
  token: string,
  query: string,
  variables: Record<string, unknown>,
  schema: z.ZodType<T>
): Promise<T> => {
  const { data } = await githubRequest({
    method: "POST",
    path: "/graphql",
    token,
    body: { query, variables },
    schema: graphqlEnvelope,
  });
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
  return parseResponse({
    schema,
    data: data.data,
    method: "POST",
    path: "/graphql",
  });
};

/** `GET /app`, authenticated by the App JWT. Succeeds only when GitHub accepts the JWT. */
export const fetchAuthenticatedApp = async (jwt: string): Promise<void> => {
  await githubRequest({
    method: "GET",
    path: "/app",
    token: jwt,
    schema: z.unknown(),
  });
};

const accountSchema = z.object({ id: z.number(), login: z.string() });

/** A GitHub account: its immutable id and its current login. */
export type Account = z.infer<typeof accountSchema>;

/**
 * `GET` on a public user endpoint: the account, or `undefined` on a 404.
 *
 * A 404 doesn't prove there's no such account: GitHub also hides some that
 * still exist, a spam-flagged account for one.
 */
const fetchAccount = async (
  token: string,
  path: string
): Promise<Account | undefined> => {
  try {
    const { data } = await githubRequest({
      method: "GET",
      path,
      token,
      schema: accountSchema,
    });
    return { id: data.id, login: data.login };
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
};

/** `GET /user/{account_id}`: the account with this id, whatever its login is now. */
export const fetchAccountById = (token: string, githubUserId: string) =>
  fetchAccount(token, `/user/${segment(githubUserId)}`);

/** `GET /users/{username}`: the account that has this login now. */
export const fetchAccountByLogin = (token: string, login: string) =>
  fetchAccount(token, `/users/${segment(login)}`);

/**
 * `GET /repos/{owner}/{repo}`: the repository's immutable id and its current
 * name, or `undefined` on a 404.
 *
 * GitHub answers a renamed repository's old name with a redirect to the
 * repository's id, which `fetch` follows, so the old name still finds it. A
 * 404 means there's no such repository, or the token can't see it.
 */
export const fetchRepository = async (
  token: string,
  org: string,
  repo: string
): Promise<{ id: number; name: string } | undefined> => {
  try {
    const { data } = await githubRequest({
      method: "GET",
      path: `/repos/${segment(org)}/${segment(repo)}`,
      token,
      schema: z.object({ id: z.number(), name: z.string() }),
    });
    return { id: data.id, name: data.name };
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
};

/** `GET /orgs/{org}/installation`, authenticated by the App JWT. */
export const fetchOrgInstallation = async (
  jwt: string,
  org: string
): Promise<Installation> => {
  const { data } = await githubRequest({
    method: "GET",
    path: `/orgs/${segment(org)}/installation`,
    token: jwt,
    schema: z.object({
      id: z.number(),
      permissions: z.record(z.string(), z.enum(ACCESS_LEVELS)),
      repository_selection: z.enum(["all", "selected"]),
      suspended_at: z.string().nullish(),
      target_id: z.number(),
    }),
  });
  return {
    id: data.id,
    permissions: data.permissions,
    repositorySelection: data.repository_selection,
    suspended: Boolean(data.suspended_at),
    orgId: data.target_id,
  };
};

/** Exchanges the App JWT for an installation token scoped to the given repositories and permissions. */
export const createInstallationToken = async (
  jwt: string,
  installationId: number,
  scope: { repositories?: string[]; permissions: Permissions }
): Promise<string> => {
  const { data } = await githubRequest({
    method: "POST",
    path: `/app/installations/${installationId}/access_tokens`,
    token: jwt,
    body: scope,
    schema: z.object({ token: z.string() }),
  });
  return data.token;
};

export const listInstallationRepositories = async (
  token: string,
  page: number,
  perPage: number
): Promise<{ total: number; repositories: Repository[] }> => {
  const { data } = await githubRequest({
    method: "GET",
    path: `/installation/repositories?${new URLSearchParams({
      per_page: String(perPage),
      page: String(page),
    }).toString()}`,
    token,
    schema: z.object({
      total_count: z.number(),
      repositories: z.array(repositorySchema),
    }),
  });
  return { total: data.total_count, repositories: data.repositories };
};

/** The names of the org's custom repository roles. GitHub only has these on Enterprise Cloud. */
export const listCustomRepositoryRoles = async (
  token: string,
  org: string
): Promise<string[]> => {
  const { data } = await githubRequest({
    method: "GET",
    path: `/orgs/${segment(org)}/custom-repository-roles`,
    token,
    schema: z.object({
      custom_roles: z.array(z.object({ name: z.string() })).optional(),
    }),
  });
  return (data.custom_roles ?? []).map(({ name }) => name);
};

/** The org's base repository permission, when GitHub shows it to this token. */
export const fetchOrgBasePermission = async (
  token: string,
  org: string
): Promise<string | undefined> => {
  const { data } = await githubRequest({
    method: "GET",
    path: `/orgs/${segment(org)}`,
    token,
    schema: z.object({ default_repository_permission: z.string().nullish() }),
  });
  return data.default_repository_permission ?? undefined;
};

const membershipStateSchema = z.object({ state: z.string() });

/** `GET /orgs/{org}/memberships/{username}`: the membership state, or `undefined` for a non-member. */
export const fetchOrgMembershipState = async (
  token: string,
  org: string,
  login: string
): Promise<string | undefined> => {
  try {
    const { data } = await githubRequest({
      method: "GET",
      path: `/orgs/${segment(org)}/memberships/${segment(login)}`,
      token,
      schema: membershipStateSchema,
    });
    return data.state;
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
};

/**
 * `PUT /repos/{owner}/{repo}/collaborators/{username}`.
 *
 * 204 means the role was set. 201 means GitHub created an invitation instead,
 * whose id is returned so the caller can report it.
 */
export const putCollaborator = async (
  token: string,
  org: string,
  repo: string,
  login: string,
  permission: string
): Promise<{ invited: boolean; invitationId: number | undefined }> => {
  const { status, data } = await githubRequest({
    method: "PUT",
    path: `/repos/${segment(org)}/${segment(repo)}/collaborators/${segment(login)}`,
    token,
    body: { permission },
    // A 201 has the invitation, and a 204 has no body.
    schema: z.object({ id: z.number().optional() }).optional(),
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
    schema: z.unknown(),
  });
};

/**
 * A team: its immutable id and GraphQL node id, and the slug and name it has
 * now.
 */
export type Team = { id: number; nodeId: string; slug: string; name: string };

const teamSchema = z.object({
  id: z.number(),
  node_id: z.string(),
  slug: z.string(),
  name: z.string(),
});

const toTeam = (team: z.infer<typeof teamSchema>): Team => ({
  id: team.id,
  nodeId: team.node_id,
  slug: team.slug,
  name: team.name,
});

/** One page of `GET /orgs/{org}/teams`: the org's teams, secret ones included. */
export const listOrgTeams = async (
  token: string,
  org: string,
  page: number,
  perPage: number
): Promise<Team[]> => {
  const { data } = await githubRequest({
    method: "GET",
    path: `/orgs/${segment(org)}/teams?${new URLSearchParams({
      per_page: String(perPage),
      page: String(page),
    }).toString()}`,
    token,
    schema: z.array(teamSchema),
  });
  return data.map(toTeam);
};

/** `GET` on a team endpoint: the team, or `undefined` on a 404. */
const fetchTeam = async (
  token: string,
  path: string
): Promise<Team | undefined> => {
  try {
    const { data } = await githubRequest({
      method: "GET",
      path,
      token,
      schema: teamSchema,
    });
    return toTeam(data);
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
};

/** `GET /orgs/{org}/teams/{team_slug}`: the team that has this slug now. */
export const fetchOrgTeamBySlug = (token: string, org: string, slug: string) =>
  fetchTeam(token, `/orgs/${segment(org)}/teams/${segment(slug)}`);

// GitHub's routes for a team by its id, which a rename doesn't change, where
// the `/orgs/{org}/teams/{team_slug}` ones follow whatever team has the slug.
const teamPath = (orgId: number, teamId: string) =>
  `/organizations/${orgId}/team/${segment(teamId)}`;

const teamMembershipPath = (orgId: number, teamId: string, login: string) =>
  `${teamPath(orgId, teamId)}/memberships/${segment(login)}`;

/** `GET /organizations/{org_id}/team/{team_id}`: the team with this id, whatever its slug is now. */
export const fetchOrgTeamById = (
  token: string,
  orgId: number,
  teamId: string
) => fetchTeam(token, teamPath(orgId, teamId));

/** The roles a team membership can have, in the form the membership `PUT` takes. */
export const TEAM_ROLES = ["member", "maintainer"] as const;
export type TeamRole = (typeof TEAM_ROLES)[number];

/**
 * `GET /organizations/{org_id}/team/{team_id}/memberships/{username}`: the
 * membership's state, or `undefined` when there's none.
 *
 * GitHub counts a child team's members as the team's own here, so an `active`
 * membership isn't proof that the user is on the team itself.
 */
export const fetchTeamMembershipState = async (
  token: string,
  orgId: number,
  teamId: string,
  login: string
): Promise<string | undefined> => {
  try {
    const { data } = await githubRequest({
      method: "GET",
      path: teamMembershipPath(orgId, teamId, login),
      token,
      schema: membershipStateSchema,
    });
    return data.state;
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
};

/**
 * `PUT /organizations/{org_id}/team/{team_id}/memberships/{username}`.
 *
 * GitHub answers 200 either way, with the membership's state. `active` means
 * the membership was set. `pending` means the user isn't in the org, so GitHub
 * invited them to it instead, and any other answer is read the same way: the
 * caller takes a pending membership back, and nothing else stands between a
 * non-member and an invitation.
 */
export const putTeamMembership = async (
  token: string,
  orgId: number,
  teamId: string,
  login: string,
  role: TeamRole
): Promise<{ pending: boolean }> => {
  const { data } = await githubRequest({
    method: "PUT",
    path: teamMembershipPath(orgId, teamId, login),
    token,
    body: { role },
    schema: z.object({ state: z.string().optional() }).optional(),
  });
  return { pending: data?.state !== "active" };
};

export const deleteTeamMembership = async (
  token: string,
  orgId: number,
  teamId: string,
  login: string
): Promise<void> => {
  await githubRequest({
    method: "DELETE",
    path: teamMembershipPath(orgId, teamId, login),
    token,
    schema: z.unknown(),
  });
};

const branchProtectionPath = (org: string, repo: string, branch: string) =>
  `/repos/${segment(org)}/${segment(repo)}/branches/${segment(branch)}/protection`;

const loginSchema = z.object({ login: z.string() });

const slugSchema = z.object({ slug: z.string() });

/**
 * Who may merge into a branch without the pull request reviews its protection
 * requires: users by login, teams and apps by slug.
 */
export type BypassAllowances = {
  users: string[];
  teams: string[];
  apps: string[];
};

/**
 * `GET /repos/{owner}/{repo}/branches/{branch}/protection`: the branch's
 * bypass allowances, or `undefined` when its protection doesn't require pull
 * request reviews. GitHub answers 404 for a branch with no protection.
 */
export const fetchBypassAllowances = async (
  token: string,
  org: string,
  repo: string,
  branch: string
): Promise<BypassAllowances | undefined> => {
  const { data } = await githubRequest({
    method: "GET",
    path: branchProtectionPath(org, repo, branch),
    token,
    schema: z.object({
      required_pull_request_reviews: z
        .object({
          bypass_pull_request_allowances: z
            .object({
              users: z.array(loginSchema).optional(),
              teams: z.array(slugSchema).optional(),
              apps: z.array(slugSchema).optional(),
            })
            .optional(),
        })
        .optional(),
    }),
  });
  const reviews = data.required_pull_request_reviews;
  if (!reviews) return undefined;
  const allowances = reviews.bypass_pull_request_allowances;
  return {
    users: (allowances?.users ?? []).map(({ login }) => login),
    teams: (allowances?.teams ?? []).map(({ slug }) => slug),
    apps: (allowances?.apps ?? []).map(({ slug }) => slug),
  };
};

/**
 * `PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews`,
 * with the bypass allowances alone, so the branch's other review settings
 * stay as they are.
 *
 * GitHub replaces each list with the one sent, so all three go every time:
 * a list left out could drop someone else's entry.
 */
export const patchBypassAllowances = async (
  token: string,
  org: string,
  repo: string,
  branch: string,
  allowances: BypassAllowances
): Promise<void> => {
  await githubRequest({
    method: "PATCH",
    path: `${branchProtectionPath(org, repo, branch)}/required_pull_request_reviews`,
    token,
    body: { bypass_pull_request_allowances: allowances },
    schema: z.unknown(),
  });
};
