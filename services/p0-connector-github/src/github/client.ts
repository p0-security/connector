import { ConnectorError } from "@p0security/connector";
import { z } from "zod";

import type { AppCredentials } from "../accesses/common/definition.ts";
import { fetchGitHubPrivateKey } from "../secrets.ts";
import {
  ACCESS_LEVELS,
  type BypassAllowances,
  GitHubError,
  type Installation,
  type Permissions,
  type Repository,
  type Team,
  type TeamRole,
  createInstallationToken,
  deleteCollaborator,
  deleteTeamMembership,
  fetchAccountById,
  fetchAccountByLogin,
  fetchAuthenticatedApp,
  fetchBypassAllowances,
  fetchOrgBasePermission,
  fetchOrgInstallation,
  fetchOrgMembershipState,
  fetchOrgTeamById,
  fetchOrgTeamBySlug,
  fetchRepository,
  fetchTeamMembershipState,
  githubGraphql,
  isNotFound,
  listCustomRepositoryRoles,
  listInstallationRepositories,
  listOrgTeams,
  patchBypassAllowances,
  putCollaborator,
  putTeamMembership,
} from "./api.ts";
import {
  AppNotInstalledError,
  BranchNotProtectedError,
  BypassChangeRefusedError,
  InstallationSuspendedError,
  MissingPermissionsError,
  RepositoryNotVisibleError,
  ReviewsNotRequiredError,
  TeamChangeRefusedError,
  TeamNotFoundError,
  WildcardRuleError,
  isUnexplainedRefusal,
} from "./errors.ts";
import { newAppJwt } from "./jwt.ts";
import { toPutRole } from "./roles.ts";

// GitHub's maximum page size for paginated list endpoints and connections.
const PAGE_SIZE = 100;

/** Every permission the customer app is created with. Each token the connector mints asks for a subset. */
export const REQUIRED_PERMISSIONS: Permissions = {
  administration: "write",
  metadata: "read",
  // Write, for the `team` access: changing who is on a team is an org-level
  // write. Everything else the connector does with it is a read.
  members: "write",
  organization_custom_roles: "read",
};

/** The `wanted` permissions `granted` doesn't cover, as `name=level` like GitHub's `X-Accepted-GitHub-Permissions`. A higher level covers a lower one. */
export const missingPermissions = (
  granted: Permissions,
  wanted: Permissions
): string[] =>
  Object.entries(wanted)
    .filter(
      ([name, level]) =>
        granted[name] === undefined ||
        ACCESS_LEVELS.indexOf(granted[name]) < ACCESS_LEVELS.indexOf(level)
    )
    .map(([name, level]) => `${name}=${level}`);

// REST can't tell a direct role from an inherited one. GraphQL's permission
// sources can. The `Repository` source is the direct collaborator role.
const DIRECT_ROLE_QUERY = `query ($owner: String!, $repo: String!, $login: String!) {
  repository(owner: $owner, name: $repo) {
    collaborators(affiliation: DIRECT, login: $login, first: 1) {
      edges { permissionSources { roleName source { __typename } } }
    }
  }
}`;

const directRoleData = z.object({
  repository: z
    .object({
      collaborators: z
        .object({
          edges: z.array(
            z.object({
              permissionSources: z.array(
                z.object({
                  roleName: z.string().nullable(),
                  source: z.object({ __typename: z.string() }),
                })
              ),
            })
          ),
        })
        .nullable(),
    })
    .nullable(),
});

// Only org members come back, so a match is also proof of membership. Needs
// the org to have verified its email domain.
const MEMBERS_QUERY = `query ($org: String!, $cursor: String) {
  organization(login: $org) {
    membersWithRole(first: ${PAGE_SIZE}, after: $cursor) {
      pageInfo { endCursor hasNextPage }
      nodes { login organizationVerifiedDomainEmails(login: $org) }
    }
  }
}`;

const pageInfo = z.object({
  endCursor: z.string().nullable(),
  hasNextPage: z.boolean(),
});

type PageInfo = z.infer<typeof pageInfo>;

const membersData = z.object({
  organization: z.object({
    membersWithRole: z.object({
      pageInfo,
      nodes: z.array(
        z.object({
          login: z.string(),
          organizationVerifiedDomainEmails: z.array(z.string()),
        })
      ),
    }),
  }),
});

// REST counts a child team's members as the team's own. GraphQL can ask for
// the team's immediate members alone. They're walked, not searched: the
// connection's `query` argument is a search GitHub doesn't specify, and a
// member it missed would be read as someone who isn't on the team.
//
// The team is found by its node id, which a rename doesn't change, where
// `organization.team(slug:)` follows whatever team has the slug.
const TEAM_MEMBERS_QUERY = `query ($team: ID!, $cursor: String) {
  node(id: $team) {
    ... on Team {
      members(membership: IMMEDIATE, first: ${PAGE_SIZE}, after: $cursor) {
        pageInfo { endCursor hasNextPage }
        edges { role node { login } }
      }
    }
  }
}`;

// A node that isn't a team comes back without `members`.
const teamMembersData = z.object({
  node: z
    .object({
      members: z
        .object({
          pageInfo,
          edges: z.array(
            z.object({
              role: z.enum(["MAINTAINER", "MEMBER"]),
              node: z.object({ login: z.string() }),
            })
          ),
        })
        .optional(),
    })
    .nullable(),
});

// A rule's pattern is a branch name, or a wildcard pattern that can match
// several. REST shows the protection that applies to a branch, but not which
// rule it comes from.
const BRANCH_PROTECTION_RULES_QUERY = `query ($owner: String!, $repo: String!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    branchProtectionRules(first: ${PAGE_SIZE}, after: $cursor) {
      pageInfo { endCursor hasNextPage }
      nodes { pattern }
    }
  }
}`;

const branchProtectionRulesData = z.object({
  repository: z
    .object({
      branchProtectionRules: z.object({
        pageInfo,
        nodes: z.array(z.object({ pattern: z.string() })),
      }),
    })
    .nullable(),
});

const TEAM_ROLE_OF = {
  MAINTAINER: "maintainer",
  MEMBER: "member",
} as const satisfies Record<string, TeamRole>;

/** GitHub refuses to mint a token for a repository the installation can't see. */
const isRepositoryNotAccessible = (error: unknown): error is GitHubError =>
  error instanceof GitHubError &&
  error.status === 422 &&
  error.githubMessages.some((message) => /repositor/i.test(message));

/** Every item of a paginated listing, walking `listPage` until a page comes up short. */
const listAllPages = async <T>(
  listPage: (page: number) => Promise<T[]>,
  page = 1
): Promise<T[]> => {
  const listed = await listPage(page);
  if (listed.length < PAGE_SIZE) return listed;
  return [...listed, ...(await listAllPages(listPage, page + 1))];
};

/**
 * The first item `matches` takes, walking a GraphQL connection page by page,
 * or `undefined` when no page has one. `readPage` reads the page after
 * `cursor`, `null` for the first.
 */
const findInConnection = async <T>(
  readPage: (
    cursor: string | null
  ) => Promise<{ items: T[]; pageInfo: PageInfo }>,
  matches: (item: T) => boolean,
  cursor: string | null = null
): Promise<T | undefined> => {
  const { items, pageInfo } = await readPage(cursor);
  const match = items.find(matches);
  if (match) return match;
  const next = pageInfo.hasNextPage ? pageInfo.endCursor : null;
  return next ? findInConnection(readPage, matches, next) : undefined;
};

/** A user on a team: the team by its id, and the user by their login. */
type TeamMember = { teamId: string; login: string };

/** A branch of one of the org's repositories, by name. */
type BranchRef = { repo: string; branch: string };

type GitHubAppIdentity = {
  appId: string;
  /** The App's PEM private key, read from the customer's vault. */
  privateKey: string;
  org: string;
};

/**
 * GitHub, as the customer app installed on one org.
 *
 * Every operation mints its own installation token, asking for the least it
 * needs:
 *
 * - A role change: one repository, `administration: write`.
 * - A role read: one repository, `metadata: read`. So does listing the repo's
 *   direct collaborators, which a revoke does when GitHub won't show the
 *   account.
 * - An account lookup: GitHub's user endpoints are public and need no
 *   permission, but a token has to ask for one, so it asks for
 *   `metadata: read`. A lookup has no repository, so its token reads metadata
 *   on every repository in the installation's selection.
 * - The repository listing: `metadata: read` on every repository in the
 *   installation's selection, since listing them is the point.
 * - A repository id lookup: the same. It may be given a renamed
 *   repository's old name, and GitHub won't scope a token by that.
 * - An org read: `members: read` or `organization_custom_roles: read`. These
 *   tokens name no repositories, which GitHub reads as every repository in the
 *   installation's selection, so they also carry `metadata: read` on all of
 *   them.
 * - A team read (the listing, an id lookup, a membership): `members: read`,
 *   like any other org read.
 * - A team membership change: `members: write`, which names no repositories
 *   either.
 * - A branch protection read (a branch's bypass list, the repo's protection
 *   rules): one repository, `administration: read`.
 * - A bypass list change: one repository, `administration: write`, like a
 *   role change.
 *
 * A team is addressed by its id, through GitHub's by-id routes, which also
 * take the org's id. That comes with the installation.
 *
 * The installation is looked up from the org with the App JWT, never stored.
 * It's cached for the client's lifetime, but the JWT isn't: it expires
 * minutes after it's signed, so each call that needs it signs a fresh one.
 */
export const newGitHubClient = (identity: GitHubAppIdentity) => {
  const { appId, privateKey, org } = identity;
  const appJwt = () => newAppJwt({ appId, privateKey });

  let installation: Promise<Installation> | undefined;
  /** The app's installation on the org. Rejects with {@link AppNotInstalledError} when there's none. */
  const fetchInstallation = () =>
    (installation ??= fetchOrgInstallation(appJwt(), org).catch(
      (error: unknown) => {
        if (isNotFound(error)) throw new AppNotInstalledError();
        throw error;
      }
    ));

  const mintToken = async (scope: {
    repo?: string;
    permissions: Permissions;
  }): Promise<string> => {
    const { id, permissions: granted, suspended } = await fetchInstallation();
    // Both checked here rather than left to GitHub, whose refusals are vaguer.
    // A suspension that lands after this lookup is still caught from GitHub's
    // 403, in toConnectorError.
    if (suspended) throw new InstallationSuspendedError();
    const missing = missingPermissions(granted, scope.permissions);
    if (missing.length > 0) throw new MissingPermissionsError(missing);
    try {
      return await createInstallationToken(appJwt(), id, {
        // Left out when there's no repo, which GitHub reads as every
        // repository in the installation's selection.
        repositories: scope.repo ? [scope.repo] : undefined,
        permissions: scope.permissions,
      });
    } catch (error) {
      if (scope.repo && isRepositoryNotAccessible(error)) {
        throw new RepositoryNotVisibleError(scope.repo);
      }
      throw error;
    }
  };

  const repoReadToken = (repo: string) =>
    mintToken({ repo, permissions: { metadata: "read" } });

  const repoWriteToken = (repo: string) =>
    mintToken({ repo, permissions: { administration: "write" } });

  const repoAdminReadToken = (repo: string) =>
    mintToken({ repo, permissions: { administration: "read" } });

  // No repo, so the token also reads metadata on every repo in the selection.
  const orgReadToken = (permission: "members" | "organization_custom_roles") =>
    mintToken({ permissions: { [permission]: "read" } });

  const membersWriteToken = () =>
    mintToken({ permissions: { members: "write" } });

  /** The org's id, which GitHub's by-id team routes take. */
  const fetchOrgId = async (): Promise<number> =>
    (await fetchInstallation()).orgId;

  /**
   * Runs a change to who is on a team with a `members: write` token. A 403
   * from the change itself that nothing else explains is how GitHub refuses
   * one on a team it won't let the app manage.
   */
  const changeTeamMembers = async <T>(
    change: (token: string, orgId: number) => Promise<T>
  ): Promise<T> => {
    const token = await membersWriteToken();
    const orgId = await fetchOrgId();
    try {
      return await change(token, orgId);
    } catch (error) {
      if (!isUnexplainedRefusal(error)) throw error;
      throw new TeamChangeRefusedError(error.githubMessages);
    }
  };

  /** The pattern of every branch protection rule on `repo`, from the page after `cursor` on. */
  const fetchProtectionPatterns = async (
    token: string,
    repo: string,
    cursor: string | null = null
  ): Promise<string[]> => {
    const data = await githubGraphql(
      token,
      BRANCH_PROTECTION_RULES_QUERY,
      { owner: org, repo, cursor },
      branchProtectionRulesData
    ).catch((error: unknown) => {
      if (isNotFound(error) && error.graphqlPath === "repository") {
        throw new RepositoryNotVisibleError(repo);
      }
      throw error;
    });
    if (!data.repository) throw new RepositoryNotVisibleError(repo);
    const { nodes, pageInfo } = data.repository.branchProtectionRules;
    const patterns = nodes.map(({ pattern }) => pattern);
    const next = pageInfo.hasNextPage ? pageInfo.endCursor : null;
    if (!next) return patterns;
    return [...patterns, ...(await fetchProtectionPatterns(token, repo, next))];
  };

  return {
    /** Whether GitHub accepts the App JWT, i.e. the app id and key belong together. */
    verifyAppJwt: async (): Promise<boolean> => {
      try {
        await fetchAuthenticatedApp(appJwt());
        return true;
      } catch (error) {
        if (
          error instanceof GitHubError &&
          (error.status === 401 || error.status === 404)
        ) {
          return false;
        }
        throw error;
      }
    },

    fetchInstallation,

    /**
     * Every repository in the installation's repository selection, walking
     * `/installation/repositories` page by page.
     *
     * The token reads metadata on the whole selection: that is what is listed.
     */
    listRepositories: async (): Promise<Repository[]> => {
      const token = await mintToken({ permissions: { metadata: "read" } });
      const listFrom = async (
        page: number,
        listed: Repository[]
      ): Promise<Repository[]> => {
        const data = await listInstallationRepositories(token, page, PAGE_SIZE);
        const repositories = [...listed, ...data.repositories];
        return data.repositories.length === 0 ||
          repositories.length >= data.total
          ? repositories
          : listFrom(page + 1, repositories);
      };
      return listFrom(1, []);
    },

    /**
     * `repo`'s repository id as a string, and its name now, or `null` when
     * the installation can't see it. A renamed repository's old name finds it
     * too.
     */
    fetchRepository: async (
      repo: string
    ): Promise<{ repositoryId: string; name: string } | null> => {
      const repository = await fetchRepository(
        await mintToken({ permissions: { metadata: "read" } }),
        org,
        repo
      );
      return repository
        ? { repositoryId: String(repository.id), name: repository.name }
        : null;
    },

    listCustomRoles: async (): Promise<string[]> =>
      listCustomRepositoryRoles(
        await orgReadToken("organization_custom_roles"),
        org
      ),

    /** The org's base repository permission, if GitHub shows it to an installation token. */
    fetchBasePermission: async (): Promise<string | undefined> =>
      fetchOrgBasePermission(await orgReadToken("members"), org),

    /** Whether `login` is an active member of the org. A pending invitation doesn't count. */
    verifyOrgMembership: async (login: string): Promise<boolean> =>
      (await fetchOrgMembershipState(
        await orgReadToken("members"),
        org,
        login
      )) === "active",

    /** The login of the org member with `email` as a verified-domain email, or `null`. */
    findMemberLogin: async (email: string): Promise<string | null> => {
      const token = await orgReadToken("members");
      const wanted = email.toLowerCase();
      const match = await findInConnection(
        async (cursor) => {
          const data = await githubGraphql(
            token,
            MEMBERS_QUERY,
            { org, cursor },
            membersData
          );
          const { nodes, pageInfo } = data.organization.membersWithRole;
          return { items: nodes, pageInfo };
        },
        (node) =>
          node.organizationVerifiedDomainEmails.some(
            (address) => address.toLowerCase() === wanted
          )
      );
      return match?.login ?? null;
    },

    /** `login`'s direct collaborator role on `repo`, in PUT form, or `null` when they have none. Team and org access are ignored. */
    fetchDirectRole: async (
      repo: string,
      login: string
    ): Promise<string | null> => {
      const token = await repoReadToken(repo);
      const data = await githubGraphql(
        token,
        DIRECT_ROLE_QUERY,
        { owner: org, repo, login },
        directRoleData
      ).catch((error: unknown) => {
        if (isNotFound(error) && error.graphqlPath === "repository") {
          throw new RepositoryNotVisibleError(repo);
        }
        throw error;
      });
      if (!data.repository) throw new RepositoryNotVisibleError(repo);
      const { collaborators } = data.repository;
      if (!collaborators) {
        // A null connection means the token couldn't read the collaborators.
        // Treating it as "no direct role" would let a revoke report success.
        throw new GitHubError({
          method: "POST",
          path: "/graphql",
          status: 403,
          githubMessages: [`GitHub didn't return the collaborators of ${repo}`],
        });
      }
      const direct = collaborators.edges[0]?.permissionSources.find(
        ({ source }) => source.__typename === "Repository"
      );
      if (!direct) return null;
      if (!direct.roleName) {
        throw new ConnectorError({
          type: "unknown",
          message: `GitHub reported a direct role for ${login} on ${repo} without naming it`,
          payload: { org, repo, login },
        });
      }
      return toPutRole(direct.roleName);
    },

    putRole: async (repo: string, login: string, role: string) =>
      putCollaborator(await repoWriteToken(repo), org, repo, login, role),

    removeCollaborator: async (repo: string, login: string): Promise<void> =>
      deleteCollaborator(await repoWriteToken(repo), org, repo, login),

    /** Every team in the org, secret ones included. */
    listTeams: async (): Promise<Team[]> => {
      const token = await orgReadToken("members");
      return listAllPages((page) => listOrgTeams(token, org, page, PAGE_SIZE));
    },

    /**
     * The team that has `slug` now, with its id as a string, or `null` when
     * the org has none. The id is what every other team call takes: a slug
     * changes when the team is renamed, and can then name another team.
     */
    fetchTeam: async (
      slug: string
    ): Promise<{ teamId: string; slug: string } | null> => {
      const team = await fetchOrgTeamBySlug(
        await orgReadToken("members"),
        org,
        slug
      );
      return team ? { teamId: String(team.id), slug: team.slug } : null;
    },

    /** The slug the team with `teamId` has now, or `null` when the org has no such team any more. */
    fetchCurrentTeamSlug: async (teamId: string): Promise<string | null> =>
      (
        await fetchOrgTeamById(
          await orgReadToken("members"),
          await fetchOrgId(),
          teamId
        )
      )?.slug ?? null,

    /**
     * `login`'s own membership of the team, as the role it has, or `null`
     * when they aren't on it. Membership of a child team doesn't count, and
     * nor does a pending invitation.
     *
     * Someone GitHub doesn't count as a member at all is the common case, and
     * takes one call. Only for someone it does are the team's own members
     * walked, to tell their membership from one they inherit.
     */
    fetchTeamMembership: async (
      member: TeamMember
    ): Promise<TeamRole | null> => {
      const { teamId, login } = member;
      const token = await orgReadToken("members");
      const orgId = await fetchOrgId();
      const team = await fetchOrgTeamById(token, orgId, teamId);
      if (!team) throw new TeamNotFoundError(teamId);
      const state = await fetchTeamMembershipState(token, orgId, teamId, login);
      if (state !== "active") return null;

      const wanted = login.toLowerCase();
      const match = await findInConnection(
        async (cursor) => {
          const data = await githubGraphql(
            token,
            TEAM_MEMBERS_QUERY,
            { team: team.nodeId, cursor },
            teamMembersData
          ).catch((error: unknown) => {
            // Deleted since the lookup above.
            if (isNotFound(error) && error.graphqlPath === "node") {
              throw new TeamNotFoundError(teamId);
            }
            throw error;
          });
          const members = data.node?.members;
          if (!members) throw new TeamNotFoundError(teamId);
          return { items: members.edges, pageInfo: members.pageInfo };
        },
        ({ node }) => node.login.toLowerCase() === wanted
      );
      return match ? TEAM_ROLE_OF[match.role] : null;
    },

    /**
     * Sets `login`'s membership of the team to `role`. `pending` means GitHub
     * invited them to the org instead, because they aren't in it.
     */
    putTeamMembership: (
      membership: TeamMember & { role: TeamRole }
    ): Promise<{ pending: boolean }> => {
      const { teamId, login, role } = membership;
      return changeTeamMembers((token, orgId) =>
        putTeamMembership(token, orgId, teamId, login, role)
      );
    },

    /**
     * Takes `login` off the team, cancelling a pending membership too. A 404
     * is read as no membership to remove, which succeeds, so running it again
     * changes nothing.
     */
    removeTeamMembership: ({ teamId, login }: TeamMember): Promise<void> =>
      changeTeamMembers(async (token, orgId) => {
        try {
          await deleteTeamMembership(token, orgId, teamId, login);
        } catch (error) {
          if (!isNotFound(error)) throw error;
        }
      }),

    /**
     * Who may merge into the branch without its required reviews.
     *
     * Only for a branch with a protection rule of its own, one whose pattern
     * is the branch's exact name: GitHub applies that rule ahead of any
     * wildcard rule that also matches, so it's the one a change edits. A
     * branch protected only by a wildcard rule throws
     * {@link WildcardRuleError}, one with no protection
     * {@link BranchNotProtectedError}, and one whose protection doesn't
     * require reviews {@link ReviewsNotRequiredError}.
     */
    fetchBypassAllowances: async (
      ref: BranchRef
    ): Promise<BypassAllowances> => {
      const { repo, branch } = ref;
      const token = await repoAdminReadToken(repo);
      const allowances = await fetchBypassAllowances(
        token,
        org,
        repo,
        branch
      ).catch((error: unknown) => {
        if (isNotFound(error)) {
          throw new BranchNotProtectedError({ repo, branch });
        }
        throw error;
      });
      if (!allowances) throw new ReviewsNotRequiredError({ repo, branch });
      const patterns = await fetchProtectionPatterns(token, repo);
      if (!patterns.includes(branch)) {
        throw new WildcardRuleError({ repo, branch });
      }
      return allowances;
    },

    /**
     * Replaces the branch's bypass lists with `allowances`. A 422 is GitHub
     * refusing the change: a user without write access, or a full list.
     */
    setBypassAllowances: async (
      change: BranchRef & { allowances: BypassAllowances }
    ): Promise<void> => {
      const { repo, branch, allowances } = change;
      const token = await repoWriteToken(repo);
      try {
        await patchBypassAllowances(token, org, repo, branch, allowances);
      } catch (error) {
        if (error instanceof GitHubError && error.status === 422) {
          throw new BypassChangeRefusedError(
            { repo, branch },
            error.githubMessages
          );
        }
        throw error;
      }
    },

    /** The pattern of every branch protection rule on `repo`, wildcard or not. */
    listProtectionPatterns: async (ref: { repo: string }): Promise<string[]> =>
      fetchProtectionPatterns(await repoAdminReadToken(ref.repo), ref.repo),

    /**
     * The current login of the account with `githubUserId`, or `null` when
     * GitHub answers 404: the account was deleted, or GitHub hides it (a
     * spam-flagged account, for one).
     *
     * A login can change, and a collaborator role moves with the account, so a
     * grant or revoke acts on the login this returns, not the one P0 saw.
     */
    fetchCurrentLogin: async (githubUserId: string): Promise<string | null> =>
      (
        await fetchAccountById(
          await mintToken({ permissions: { metadata: "read" } }),
          githubUserId
        )
      )?.login ?? null,

    /** The account that has `login` now, with its GitHub user id as a string, or `null` when there's none. */
    fetchAccount: async (
      login: string
    ): Promise<{ githubUserId: string; login: string } | null> => {
      const account = await fetchAccountByLogin(
        await mintToken({ permissions: { metadata: "read" } }),
        login
      );
      return account
        ? { githubUserId: String(account.id), login: account.login }
        : null;
    },
  };
};

export type GitHubClient = ReturnType<typeof newGitHubClient>;

/** Builds a {@link GitHubClient} for the customer app, reading its key from the customer's vault. */
export type ConnectGitHub = (
  credentials: AppCredentials
) => Promise<GitHubClient>;

export const connectGitHub: ConnectGitHub = async (credentials) => {
  const { org, appId, privateKey } = credentials;
  return newGitHubClient({
    org,
    appId,
    privateKey: await fetchGitHubPrivateKey(privateKey),
  });
};
