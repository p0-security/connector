import { ConnectorError } from "@p0security/connector-core";

import type { AppCredentials } from "../accesses/role/definition.ts";
import { getGithubPrivateKey } from "../secrets.ts";
import {
  ACCESS_LEVELS,
  GitHubError,
  type Installation,
  type Permissions,
  type Repository,
  createInstallationToken,
  deleteCollaborator,
  deleteInvitation,
  getAccountById,
  getAccountByLogin,
  getAuthenticatedApp,
  getOrgBasePermission,
  getOrgInstallation,
  getOrgMembershipState,
  getRepository,
  githubGraphql,
  listCustomRepositoryRoles,
  listInstallationRepositories,
  listRepositoryInvitations,
  putCollaborator,
} from "./api.ts";
import {
  AppNotInstalledError,
  InstallationSuspendedError,
  MissingPermissionsError,
  RepositoryNotVisibleError,
} from "./errors.ts";
import { createAppJwt } from "./jwt.ts";
import { toPutRole } from "./roles.ts";

// GitHub's maximum page size for paginated list endpoints and connections.
const PAGE_SIZE = 100;

/** Every permission the customer app is created with. Each token the connector mints asks for a subset. */
export const REQUIRED_PERMISSIONS: Permissions = {
  administration: "write",
  metadata: "read",
  members: "read",
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

// REST can't tell a direct role from an inherited one; GraphQL's permission
// sources can. The `Repository` source is the direct collaborator role.
const DIRECT_ROLE_QUERY = `query ($owner: String!, $repo: String!, $login: String!) {
  repository(owner: $owner, name: $repo) {
    collaborators(affiliation: DIRECT, login: $login, first: 1) {
      edges { permissionSources { roleName source { __typename } } }
    }
  }
}`;

type DirectRoleData = {
  repository: {
    collaborators: {
      edges: {
        permissionSources: {
          roleName: string | null;
          source: { __typename: string };
        }[];
      }[];
    } | null;
  } | null;
};

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

type MembersData = {
  organization: {
    membersWithRole: {
      pageInfo: { endCursor: string | null; hasNextPage: boolean };
      nodes: { login: string; organizationVerifiedDomainEmails: string[] }[];
    };
  };
};

/** GitHub refuses to mint a token for a repository the installation can't see. */
const isRepositoryNotAccessible = (error: unknown) =>
  error instanceof GitHubError &&
  error.status === 422 &&
  error.githubMessages.some((message) => /repositor/i.test(message));

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
 * - a role change: one repository, `administration: write`. So does the
 *   invitation sequence (listing the repo's invitations and cancelling the
 *   app's), which shares one token from start to finish;
 * - a role read: one repository, `metadata: read`. So does listing the repo's
 *   direct collaborators, which a revoke does when GitHub won't show the
 *   account;
 * - an account lookup: GitHub's user endpoints are public and need no
 *   permission, but a token has to ask for one, so it asks for
 *   `metadata: read`. A lookup has no repository, so its token reads metadata
 *   on every repository in the installation's selection;
 * - the repository listing: `metadata: read` on every repository in the
 *   installation's selection, since listing them is the point;
 * - a repository id lookup: the same. It may be given a renamed
 *   repository's old name, and GitHub won't scope a token by that;
 * - an org read: `members: read` or `organization_custom_roles: read`. These
 *   tokens name no repositories, which GitHub reads as every repository in the
 *   installation's selection, so they also carry `metadata: read` on all of
 *   them.
 *
 * The installation is looked up from the org with the App JWT, never stored,
 * and so is the app's slug when the invitation sequence needs it. Both are
 * cached for the client's lifetime, but the JWT isn't: it expires minutes
 * after it's signed, so each call that needs it signs a fresh one.
 */
export const newGitHubClient = ({
  appId,
  privateKey,
  org,
}: GitHubAppIdentity) => {
  const appJwt = () => createAppJwt({ appId, privateKey });

  let installation: Promise<Installation> | undefined;
  /** The app's installation on the org. Rejects with {@link AppNotInstalledError} when there's none. */
  const findInstallation = () =>
    (installation ??= getOrgInstallation(appJwt(), org).catch(
      (error: unknown) => {
        if (error instanceof GitHubError && error.status === 404) {
          throw new AppNotInstalledError();
        }
        throw error;
      }
    ));

  const mintToken = async (scope: {
    repo?: string;
    permissions: Permissions;
  }): Promise<string> => {
    const { id, permissions: granted, suspended } = await findInstallation();
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
  // No repo, so the token also reads metadata on every repo in the selection.
  const orgReadToken = (permission: "members" | "organization_custom_roles") =>
    mintToken({ permissions: { [permission]: "read" } });

  let botLogin: Promise<string> | undefined;

  return {
    /** Whether GitHub accepts the App JWT, i.e. the app id and key belong together. */
    isAppJwtAccepted: async (): Promise<boolean> => {
      try {
        await getAuthenticatedApp(appJwt());
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

    findInstallation,

    /**
     * The login GitHub attributes the app's own actions to, `<slug>[bot]`,
     * with the slug read from `GET /app`. It's the inviter on an invitation
     * the app's `PUT` created.
     */
    appBotLogin: (): Promise<string> =>
      (botLogin ??= getAuthenticatedApp(appJwt()).then(({ slug }) => {
        if (!slug)
          throw new Error("GitHub didn't return the GitHub App's slug");
        return `${slug}[bot]`;
      })),

    /**
     * Every repository in the installation's repository selection, walking
     * `/installation/repositories` page by page.
     *
     * The token reads metadata on the whole selection: that is what is listed.
     */
    listRepositories: async (): Promise<Repository[]> => {
      const token = await mintToken({ permissions: { metadata: "read" } });
      const repositories: Repository[] = [];
      for (let page = 1; ; page++) {
        const data = await listInstallationRepositories(token, page, PAGE_SIZE);
        repositories.push(...data.repositories);
        if (data.repositories.length === 0 || repositories.length >= data.total)
          return repositories;
      }
    },

    /**
     * `repo`'s repository id as a string, and its name now, or `null` when
     * the installation can't see it. A renamed repository's old name finds it
     * too.
     */
    findRepository: async (
      repo: string
    ): Promise<{ repositoryId: string; name: string } | null> => {
      const repository = await getRepository(
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
    basePermission: async (): Promise<string | undefined> =>
      getOrgBasePermission(await orgReadToken("members"), org),

    /** Whether `login` is an active member of the org. A pending invitation doesn't count. */
    isMember: async (login: string): Promise<boolean> =>
      (await getOrgMembershipState(
        await orgReadToken("members"),
        org,
        login
      )) === "active",

    /** The login of the org member with `email` as a verified-domain email, or `null`. */
    findMemberLogin: async (email: string): Promise<string | null> => {
      const token = await orgReadToken("members");
      const wanted = email.toLowerCase();
      let cursor: string | null = null;
      do {
        const data: MembersData = await githubGraphql(token, MEMBERS_QUERY, {
          org,
          cursor,
        });
        const { nodes, pageInfo } = data.organization.membersWithRole;
        const match = nodes.find((node) =>
          node.organizationVerifiedDomainEmails.some(
            (address) => address.toLowerCase() === wanted
          )
        );
        if (match) return match.login;
        cursor = pageInfo.hasNextPage ? pageInfo.endCursor : null;
      } while (cursor);
      return null;
    },

    /** `login`'s direct collaborator role on `repo`, in PUT form, or `null` when they have none. Team and org access are ignored. */
    readDirectRole: async (
      repo: string,
      login: string
    ): Promise<string | null> => {
      const token = await repoReadToken(repo);
      let data: DirectRoleData;
      try {
        data = await githubGraphql(token, DIRECT_ROLE_QUERY, {
          owner: org,
          repo,
          login,
        });
      } catch (error) {
        if (
          error instanceof GitHubError &&
          error.status === 404 &&
          error.graphqlPath === "repository"
        ) {
          throw new RepositoryNotVisibleError(repo);
        }
        throw error;
      }
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

    /**
     * `repo`'s invitations, through one `administration: write` token minted
     * here and shared by every call that follows.
     */
    repositoryInvitations: async (repo: string) => {
      const token = await repoWriteToken(repo);
      return {
        cancel: (invitationId: number): Promise<void> =>
          deleteInvitation(token, org, repo, invitationId),

        /**
         * The ids of the repo's pending invitations that `inviter` sent
         * `invitee`, both matched ignoring case. Pass the app's
         * {@link GitHubClient.appBotLogin} as `inviter`, and an admin's
         * invitation to the same login isn't included.
         */
        findInvitationIds: async (params: {
          invitee: string;
          inviter: string;
        }): Promise<number[]> => {
          const invitee = params.invitee.toLowerCase();
          const inviter = params.inviter.toLowerCase();
          const ids: number[] = [];
          for (let page = 1; ; page++) {
            const invitations = await listRepositoryInvitations(
              token,
              org,
              repo,
              page,
              PAGE_SIZE
            );
            ids.push(
              ...invitations
                .filter(
                  (invitation) =>
                    invitation.invitee?.login.toLowerCase() === invitee &&
                    invitation.inviter?.login.toLowerCase() === inviter
                )
                .map(({ id }) => id)
            );
            if (invitations.length < PAGE_SIZE) return ids;
          }
        },
      };
    },

    /**
     * The current login of the account with `githubUserId`, or `null` when
     * GitHub answers 404: the account was deleted, or GitHub hides it (a
     * spam-flagged account, for one).
     *
     * A login can change, and a collaborator role moves with the account, so a
     * grant or revoke acts on the login this returns, not the one P0 saw.
     */
    currentLogin: async (githubUserId: string): Promise<string | null> =>
      (
        await getAccountById(
          await mintToken({ permissions: { metadata: "read" } }),
          githubUserId
        )
      )?.login ?? null,

    /** The account that has `login` now, with its GitHub user id as a string, or `null` when there's none. */
    findAccount: async (
      login: string
    ): Promise<{ githubUserId: string; login: string } | null> => {
      const account = await getAccountByLogin(
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

/** A repo's invitations, all through one token: see {@link GitHubClient.repositoryInvitations}. */
export type RepositoryInvitations = Awaited<
  ReturnType<GitHubClient["repositoryInvitations"]>
>;

/** Builds a {@link GitHubClient} for the customer app, reading its key from the customer's vault. */
export type ConnectGitHub = (
  credentials: AppCredentials
) => Promise<GitHubClient>;

export const connectGitHub: ConnectGitHub = async ({
  org,
  appId,
  privateKey,
}) =>
  newGitHubClient({
    org,
    appId,
    privateKey: await getGithubPrivateKey(privateKey),
  });
