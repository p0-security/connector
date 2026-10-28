import { beforeEach, describe, expect, it, vi } from "vitest";

import type * as apiModule from "../api.ts";
import { GitHubError, type Installation } from "../api.ts";
import { missingPermissions, newGitHubClient } from "../client.ts";
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
} from "../errors.ts";

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factories run.
const api = vi.hoisted(() => ({
  createInstallationToken: vi.fn(),
  fetchAuthenticatedApp: vi.fn(),
  fetchOrgInstallation: vi.fn(),
  githubGraphql: vi.fn(),
  listInstallationRepositories: vi.fn(),
  fetchOrgMembershipState: vi.fn(),
  putCollaborator: vi.fn(),
  deleteCollaborator: vi.fn(),
  fetchAccountById: vi.fn(),
  fetchAccountByLogin: vi.fn(),
  fetchRepository: vi.fn(),
  listOrgTeams: vi.fn(),
  fetchOrgTeamBySlug: vi.fn(),
  fetchOrgTeamById: vi.fn(),
  fetchTeamMembershipState: vi.fn(),
  putTeamMembership: vi.fn(),
  deleteTeamMembership: vi.fn(),
  fetchBypassAllowances: vi.fn(),
  patchBypassAllowances: vi.fn(),
}));

const newAppJwt = vi.hoisted(() => vi.fn(() => "signed-jwt"));
vi.mock("../jwt.ts", () => ({ newAppJwt }));
vi.mock("../api.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof apiModule>()),
  ...api,
}));

const INSTALLATION: Installation = {
  id: 42,
  permissions: {
    administration: "write",
    metadata: "read",
    members: "write",
    organization_custom_roles: "read",
  },
  repositorySelection: "selected",
  suspended: false,
  orgId: 9919,
};

const REPO_WRITE_SCOPE = {
  repositories: ["api"],
  permissions: { administration: "write" },
};

const MEMBERS_WRITE_SCOPE = {
  repositories: undefined,
  permissions: { members: "write" },
};

const TEAM = { id: 7, nodeId: "T_7", slug: "platform", name: "Platform" };
const TEAM_MEMBERSHIP_PATH = "/organizations/9919/team/7/memberships/octocat";

const failed = (method: "DELETE" | "PUT", status: number, message: string) =>
  new GitHubError({
    method,
    path: TEAM_MEMBERSHIP_PATH,
    status,
    githubMessages: [message],
  });

const teamMembersResponse = (
  edges: { role: "MAINTAINER" | "MEMBER"; login: string }[],
  pageInfo: { endCursor: string | null; hasNextPage: boolean } = {
    endCursor: null,
    hasNextPage: false,
  }
) => ({
  node: {
    members: {
      pageInfo,
      edges: edges.map(({ role, login }) => ({ role, node: { login } })),
    },
  },
});

const newClient = () =>
  newGitHubClient({ appId: "123456", privateKey: "PEM", org: "acme" });

const directRoleResponse = (
  sources: { roleName: string | null; source: { __typename: string } }[]
) => ({
  repository: {
    collaborators: {
      edges: sources.length ? [{ permissionSources: sources }] : [],
    },
  },
});

beforeEach(() => {
  vi.clearAllMocks();
  api.fetchOrgInstallation.mockResolvedValue(INSTALLATION);
  api.createInstallationToken.mockResolvedValue("ghs_scoped");
});

describe("installation tokens", () => {
  it("finds the installation from the org, once per client", async () => {
    const client = newClient();
    api.githubGraphql.mockResolvedValue(directRoleResponse([]));

    await client.fetchDirectRole("api", "octocat");
    await client.fetchDirectRole("api", "octocat");

    expect(api.fetchOrgInstallation).toHaveBeenCalledTimes(1);
    expect(api.fetchOrgInstallation).toHaveBeenCalledWith("signed-jwt", "acme");
  });

  it("reports an org with no installation as not installed", async () => {
    api.fetchOrgInstallation.mockRejectedValue(
      new GitHubError({
        method: "GET",
        path: "/orgs/acme/installation",
        status: 404,
        githubMessages: ["Not Found"],
      })
    );

    await expect(newClient().fetchInstallation()).rejects.toBeInstanceOf(
      AppNotInstalledError
    );
  });

  // A JWT expires minutes after it's signed, and a client can outlive that.
  it("signs a fresh App JWT for every call that needs one", async () => {
    const client = newClient();
    api.githubGraphql.mockResolvedValue(directRoleResponse([]));
    newAppJwt
      .mockReturnValueOnce("jwt-1")
      .mockReturnValueOnce("jwt-2")
      .mockReturnValueOnce("jwt-3");

    await client.fetchDirectRole("api", "octocat");
    await client.fetchDirectRole("api", "octocat");

    expect(api.fetchOrgInstallation).toHaveBeenCalledWith("jwt-1", "acme");
    expect(api.createInstallationToken.mock.calls.map(([jwt]) => jwt)).toEqual([
      "jwt-2",
      "jwt-3",
    ]);
    expect(newAppJwt).toHaveBeenCalledWith({
      appId: "123456",
      privateKey: "PEM",
    });
  });

  it("mints a fresh token per call", async () => {
    const client = newClient();
    api.githubGraphql.mockResolvedValue(directRoleResponse([]));

    await client.fetchDirectRole("api", "octocat");
    await client.fetchDirectRole("api", "octocat");

    expect(api.createInstallationToken).toHaveBeenCalledTimes(2);
  });

  it("scopes a role change to one repo with administration: write", async () => {
    api.putCollaborator.mockResolvedValue({ invited: false });

    await newClient().putRole("api", "octocat", "push");

    expect(api.createInstallationToken).toHaveBeenCalledWith(
      "signed-jwt",
      42,
      REPO_WRITE_SCOPE
    );
    expect(api.putCollaborator).toHaveBeenCalledWith(
      "ghs_scoped",
      "acme",
      "api",
      "octocat",
      "push"
    );
  });

  it("scopes removing a collaborator to one repo with administration: write", async () => {
    await newClient().removeCollaborator("api", "octocat");

    expect(api.createInstallationToken).toHaveBeenCalledWith(
      "signed-jwt",
      42,
      REPO_WRITE_SCOPE
    );
    expect(api.deleteCollaborator).toHaveBeenCalledWith(
      "ghs_scoped",
      "acme",
      "api",
      "octocat"
    );
  });

  // A team isn't a repository's, so its token names none.
  it("scopes a team membership change to members: write, naming no repos", async () => {
    api.putTeamMembership.mockResolvedValue({ pending: false });

    await newClient().putTeamMembership({
      teamId: "7",
      login: "octocat",
      role: "member",
    });

    expect(api.createInstallationToken).toHaveBeenCalledWith(
      "signed-jwt",
      42,
      MEMBERS_WRITE_SCOPE
    );
    // By the org's id and the team's, which a rename changes neither of.
    expect(api.putTeamMembership).toHaveBeenCalledWith(
      "ghs_scoped",
      9919,
      "7",
      "octocat",
      "member"
    );
  });

  it("scopes removing a team membership to members: write, naming no repos", async () => {
    await newClient().removeTeamMembership({ teamId: "7", login: "octocat" });

    expect(api.createInstallationToken).toHaveBeenCalledWith(
      "signed-jwt",
      42,
      MEMBERS_WRITE_SCOPE
    );
    expect(api.deleteTeamMembership).toHaveBeenCalledWith(
      "ghs_scoped",
      9919,
      "7",
      "octocat"
    );
  });

  it.each([
    [
      "the team listing",
      async () => {
        api.listOrgTeams.mockResolvedValue([]);
        await newClient().listTeams();
      },
    ],
    [
      "a team id lookup",
      async () => {
        api.fetchOrgTeamBySlug.mockResolvedValue(TEAM);
        await newClient().fetchTeam("platform");
      },
    ],
    [
      "resolving a team's id",
      async () => {
        api.fetchOrgTeamById.mockResolvedValue(TEAM);
        await newClient().fetchCurrentTeamSlug("7");
      },
    ],
    [
      "a team membership read",
      async () => {
        api.fetchOrgTeamById.mockResolvedValue(TEAM);
        await newClient().fetchTeamMembership({
          teamId: "7",
          login: "octocat",
        });
      },
    ],
  ])("scopes %s to members: read, naming no repos", async (_case, run) => {
    await run();

    expect(api.createInstallationToken).toHaveBeenCalledTimes(1);
    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: undefined,
      permissions: { members: "read" },
    });
  });

  // What an app created before the `team` access has.
  describe("with an installation that has members: read", () => {
    beforeEach(() => {
      api.fetchOrgInstallation.mockResolvedValue({
        ...INSTALLATION,
        permissions: { ...INSTALLATION.permissions, members: "read" },
      });
    });

    it("still mints the tokens the role access asks for", async () => {
      api.putCollaborator.mockResolvedValue({ invited: false });
      api.fetchOrgMembershipState.mockResolvedValue("active");
      const client = newClient();

      await client.putRole("api", "octocat", "push");
      await expect(client.verifyOrgMembership("octocat")).resolves.toBe(true);
    });

    it("still reads teams", async () => {
      api.listOrgTeams.mockResolvedValue([TEAM]);

      await expect(newClient().listTeams()).resolves.toEqual([TEAM]);
    });

    it.each([
      [
        "a team membership",
        (client: ReturnType<typeof newClient>) =>
          client.putTeamMembership({
            teamId: "7",
            login: "octocat",
            role: "member",
          }),
      ],
      [
        "removing a team membership",
        (client: ReturnType<typeof newClient>) =>
          client.removeTeamMembership({ teamId: "7", login: "octocat" }),
      ],
    ])("refuses %s before asking GitHub for a token", async (_case, run) => {
      const error = await run(newClient()).catch((e: unknown) => e);

      expect(error).toBeInstanceOf(MissingPermissionsError);
      expect((error as MissingPermissionsError).permissions).toEqual([
        "members=write",
      ]);
      expect(api.createInstallationToken).not.toHaveBeenCalled();
    });
  });

  // The user endpoints are public, but a token has to ask for something.
  it("scopes resolving a GitHub user id to metadata: read, naming no repos", async () => {
    api.fetchAccountById.mockResolvedValue({ id: 583231, login: "octocat" });

    await newClient().fetchCurrentLogin("583231");

    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: undefined,
      permissions: { metadata: "read" },
    });
  });

  it("scopes the account listing to metadata: read, naming no repos", async () => {
    api.fetchAccountByLogin.mockResolvedValue({ id: 583231, login: "octocat" });

    await newClient().fetchAccount("octocat");

    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: undefined,
      permissions: { metadata: "read" },
    });
  });

  // It may be given a renamed repository's old name, which can't scope a token.
  it("scopes a repository id lookup to metadata: read, naming no repos", async () => {
    api.fetchRepository.mockResolvedValue({ id: 1296269, name: "api" });

    await newClient().fetchRepository("old-api");

    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: undefined,
      permissions: { metadata: "read" },
    });
  });

  it("scopes a role read to one repo with metadata: read", async () => {
    api.githubGraphql.mockResolvedValue(directRoleResponse([]));

    await newClient().fetchDirectRole("api", "octocat");

    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: ["api"],
      permissions: { metadata: "read" },
    });
  });

  // Naming no repositories means the whole selection, so this token also
  // reads metadata on every repo in it.
  it("scopes an org read to one org permission, naming no repos", async () => {
    api.fetchOrgMembershipState.mockResolvedValue("active");

    await newClient().verifyOrgMembership("octocat");

    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: undefined,
      permissions: { members: "read" },
    });
  });

  it("scopes the repository listing to metadata: read across the selection", async () => {
    api.listInstallationRepositories.mockResolvedValue({
      total: 0,
      repositories: [],
    });

    await newClient().listRepositories();

    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: undefined,
      permissions: { metadata: "read" },
    });
  });

  it("refuses to mint a token for a suspended installation", async () => {
    api.fetchOrgInstallation.mockResolvedValue({
      ...INSTALLATION,
      suspended: true,
    });

    await expect(
      newClient().putRole("api", "octocat", "push")
    ).rejects.toBeInstanceOf(InstallationSuspendedError);
    expect(api.createInstallationToken).not.toHaveBeenCalled();
  });

  it("refuses to mint a token the installation wasn't granted, naming the permission", async () => {
    api.fetchOrgInstallation.mockResolvedValue({
      ...INSTALLATION,
      permissions: { metadata: "read", members: "read" },
    });

    const error = await newClient()
      .putRole("api", "octocat", "push")
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(MissingPermissionsError);
    expect((error as MissingPermissionsError).permissions).toEqual([
      "administration=write",
    ]);
    expect(api.createInstallationToken).not.toHaveBeenCalled();
  });

  it("reports a repo outside the repository selection when GitHub won't scope a token to it", async () => {
    api.createInstallationToken.mockRejectedValue(
      new GitHubError({
        method: "POST",
        path: "/app/installations/42/access_tokens",
        status: 422,
        githubMessages: [
          "There is at least one repository that does not exist or is not accessible to the parent installation.",
        ],
      })
    );

    await expect(newClient().putRole("api", "octocat", "push")).rejects.toEqual(
      new RepositoryNotVisibleError("api")
    );
  });
});

describe("fetchDirectRole", () => {
  it("returns the Repository source's role in PUT form", async () => {
    api.githubGraphql.mockResolvedValue(
      directRoleResponse([
        { roleName: "maintain", source: { __typename: "Team" } },
        { roleName: "write", source: { __typename: "Repository" } },
        { roleName: "read", source: { __typename: "Organization" } },
      ])
    );

    await expect(newClient().fetchDirectRole("api", "octocat")).resolves.toBe(
      "push"
    );
    expect(api.githubGraphql).toHaveBeenCalledWith(
      "ghs_scoped",
      expect.stringContaining("collaborators(affiliation: DIRECT"),
      { owner: "acme", repo: "api", login: "octocat" },
      expect.anything()
    );
  });

  it("normalises Triage Plus in display form", async () => {
    api.githubGraphql.mockResolvedValue(
      directRoleResponse([
        { roleName: "Triage Plus", source: { __typename: "Repository" } },
      ])
    );

    await expect(newClient().fetchDirectRole("api", "octocat")).resolves.toBe(
      "triage_plus"
    );
  });

  it("keeps a custom role's name", async () => {
    api.githubGraphql.mockResolvedValue(
      directRoleResponse([
        { roleName: "Labeler", source: { __typename: "Repository" } },
      ])
    );

    await expect(newClient().fetchDirectRole("api", "octocat")).resolves.toBe(
      "Labeler"
    );
  });

  it("returns null when the only access is inherited", async () => {
    api.githubGraphql.mockResolvedValue(
      directRoleResponse([
        { roleName: "write", source: { __typename: "Team" } },
      ])
    );

    await expect(
      newClient().fetchDirectRole("api", "octocat")
    ).resolves.toBeNull();
  });

  it("returns null for someone with no direct role", async () => {
    api.githubGraphql.mockResolvedValue(directRoleResponse([]));
    await expect(
      newClient().fetchDirectRole("api", "octocat")
    ).resolves.toBeNull();
  });

  it("reports a repo GraphQL can't resolve as not visible", async () => {
    api.githubGraphql.mockRejectedValue(
      new GitHubError({
        method: "POST",
        path: "/graphql",
        status: 404,
        githubMessages: ["Could not resolve to a Repository"],
        graphqlPath: "repository",
      })
    );

    await expect(newClient().fetchDirectRole("api", "octocat")).rejects.toEqual(
      new RepositoryNotVisibleError("api")
    );
  });

  // Reading nothing as "no direct role" would let a revoke report success.
  it("fails when GitHub returns no collaborators connection", async () => {
    api.githubGraphql.mockResolvedValue({
      repository: { collaborators: null },
    });

    const error = await newClient()
      .fetchDirectRole("api", "octocat")
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(GitHubError);
    expect((error as GitHubError).status).toBe(403);
  });
});

describe("findMemberLogin", () => {
  const page = (
    nodes: { login: string; organizationVerifiedDomainEmails: string[] }[],
    endCursor: string | null
  ) => ({
    organization: {
      membersWithRole: {
        pageInfo: { endCursor, hasNextPage: endCursor !== null },
        nodes,
      },
    },
  });

  it("pages through the members until an email matches, ignoring case", async () => {
    api.githubGraphql
      .mockResolvedValueOnce(
        page([{ login: "hubot", organizationVerifiedDomainEmails: [] }], "c1")
      )
      .mockResolvedValueOnce(
        page(
          [
            {
              login: "octocat",
              organizationVerifiedDomainEmails: ["Octocat@Acme.com"],
            },
          ],
          "c2"
        )
      );

    await expect(newClient().findMemberLogin("octocat@acme.com")).resolves.toBe(
      "octocat"
    );
    expect(api.githubGraphql).toHaveBeenCalledTimes(2);
    expect(api.githubGraphql).toHaveBeenLastCalledWith(
      "ghs_scoped",
      expect.stringContaining("organizationVerifiedDomainEmails"),
      { org: "acme", cursor: "c1" },
      expect.anything()
    );
  });

  it("returns null when no member has the email", async () => {
    api.githubGraphql.mockResolvedValue(
      page([{ login: "hubot", organizationVerifiedDomainEmails: [] }], null)
    );
    await expect(
      newClient().findMemberLogin("octocat@acme.com")
    ).resolves.toBeNull();
  });
});

describe("listRepositories", () => {
  const repo = (name: string) => ({ name, full_name: `acme/${name}` });

  // Otherwise a total GitHub never reaches would loop forever.
  it("stops on an empty page even when the total says there's more", async () => {
    api.listInstallationRepositories
      .mockResolvedValueOnce({ total: 5, repositories: [repo("a")] })
      .mockResolvedValueOnce({ total: 5, repositories: [] });

    await expect(newClient().listRepositories()).resolves.toEqual([repo("a")]);
    expect(api.listInstallationRepositories).toHaveBeenCalledTimes(2);
  });

  it("walks every page", async () => {
    api.listInstallationRepositories
      .mockResolvedValueOnce({ total: 3, repositories: [repo("a"), repo("b")] })
      .mockResolvedValueOnce({ total: 3, repositories: [repo("c")] });

    await expect(newClient().listRepositories()).resolves.toEqual([
      repo("a"),
      repo("b"),
      repo("c"),
    ]);
    expect(api.listInstallationRepositories).toHaveBeenNthCalledWith(
      2,
      "ghs_scoped",
      2,
      100
    );
  });
});

describe("listTeams", () => {
  it("walks every page", async () => {
    const firstPage = Array.from({ length: 100 }, (_, i) => ({
      id: 100 + i,
      slug: `team-${i}`,
      name: `Team ${i}`,
    }));
    api.listOrgTeams
      .mockResolvedValueOnce(firstPage)
      .mockResolvedValueOnce([TEAM]);

    await expect(newClient().listTeams()).resolves.toEqual([
      ...firstPage,
      TEAM,
    ]);
    expect(api.listOrgTeams).toHaveBeenNthCalledWith(
      2,
      "ghs_scoped",
      "acme",
      2,
      100
    );
  });
});

describe("fetchTeam", () => {
  it("returns the team's id as a string, and its slug as GitHub spells it", async () => {
    api.fetchOrgTeamBySlug.mockResolvedValue(TEAM);

    await expect(newClient().fetchTeam("Platform")).resolves.toEqual({
      teamId: "7",
      slug: "platform",
    });
    expect(api.fetchOrgTeamBySlug).toHaveBeenCalledWith(
      "ghs_scoped",
      "acme",
      "Platform"
    );
  });

  it("returns null when the org has no team with the slug", async () => {
    api.fetchOrgTeamBySlug.mockResolvedValue(undefined);

    await expect(newClient().fetchTeam("platform")).resolves.toBeNull();
  });
});

describe("fetchCurrentTeamSlug", () => {
  it("returns the slug the team has now, looked up by the org's id and its own", async () => {
    api.fetchOrgTeamById.mockResolvedValue({
      ...TEAM,
      slug: "platform-renamed",
    });

    await expect(newClient().fetchCurrentTeamSlug("7")).resolves.toBe(
      "platform-renamed"
    );
    expect(api.fetchOrgTeamById).toHaveBeenCalledWith("ghs_scoped", 9919, "7");
  });

  it("returns null when the team is gone", async () => {
    api.fetchOrgTeamById.mockResolvedValue(undefined);

    await expect(newClient().fetchCurrentTeamSlug("7")).resolves.toBeNull();
  });
});

describe("fetchTeamMembership", () => {
  beforeEach(() => {
    api.fetchOrgTeamById.mockResolvedValue(TEAM);
    api.fetchTeamMembershipState.mockResolvedValue("active");
  });

  it.each([
    ["MEMBER", "member"],
    ["MAINTAINER", "maintainer"],
  ] as const)("returns a %s's role in PUT form", async (role, expected) => {
    api.githubGraphql.mockResolvedValue(
      teamMembersResponse([{ role, login: "Octocat" }])
    );

    await expect(
      newClient().fetchTeamMembership({ teamId: "7", login: "octocat" })
    ).resolves.toBe(expected);
    expect(api.fetchTeamMembershipState).toHaveBeenCalledWith(
      "ghs_scoped",
      9919,
      "7",
      "octocat"
    );
    expect(api.githubGraphql).toHaveBeenCalledWith(
      "ghs_scoped",
      // A child team's members aren't the team's own.
      expect.stringContaining("membership: IMMEDIATE"),
      // By its node id: a rename can hand its slug to another team.
      { team: "T_7", cursor: null },
      expect.anything()
    );
  });

  // The common case, and it never walks the team.
  it.each([
    ["no membership at all", undefined],
    ["a pending membership", "pending"],
  ])("returns null for someone with %s, in one read", async (_case, state) => {
    api.fetchTeamMembershipState.mockResolvedValue(state);

    await expect(
      newClient().fetchTeamMembership({ teamId: "7", login: "octocat" })
    ).resolves.toBeNull();
    expect(api.githubGraphql).not.toHaveBeenCalled();
  });

  // A search could miss them, and a miss would be recorded as no prior
  // membership.
  it("walks every page of the team's own members, without searching", async () => {
    api.githubGraphql
      .mockResolvedValueOnce(
        teamMembersResponse([{ role: "MAINTAINER", login: "hubot" }], {
          endCursor: "c1",
          hasNextPage: true,
        })
      )
      .mockResolvedValueOnce(
        teamMembersResponse([{ role: "MEMBER", login: "octocat" }])
      );

    await expect(
      newClient().fetchTeamMembership({ teamId: "7", login: "octocat" })
    ).resolves.toBe("member");
    expect(api.githubGraphql).toHaveBeenLastCalledWith(
      "ghs_scoped",
      expect.not.stringContaining("query:"),
      { team: "T_7", cursor: "c1" },
      expect.anything()
    );
  });

  // GitHub counts them as a member, through a child team.
  it("returns null for someone who is only on a child team", async () => {
    api.githubGraphql.mockResolvedValue(
      teamMembersResponse([{ role: "MEMBER", login: "hubot" }])
    );

    await expect(
      newClient().fetchTeamMembership({ teamId: "7", login: "octocat" })
    ).resolves.toBeNull();
  });

  // Reading either as "not on the team" would record no prior membership.
  it.each([
    [
      "has no team with the id",
      () => api.fetchOrgTeamById.mockResolvedValue(undefined),
    ],
    [
      "can't resolve the team's node any more",
      () =>
        api.githubGraphql.mockRejectedValue(
          new GitHubError({
            method: "POST",
            path: "/graphql",
            status: 404,
            githubMessages: ["Could not resolve to a node with the global id"],
            graphqlPath: "node",
          })
        ),
    ],
    [
      "answers with no team for its node id",
      () => api.githubGraphql.mockResolvedValue({ node: null }),
    ],
  ])("reports the team as not found when GitHub %s", async (_case, setup) => {
    setup();

    await expect(
      newClient().fetchTeamMembership({ teamId: "7", login: "octocat" })
    ).rejects.toBeInstanceOf(TeamNotFoundError);
  });
});

describe("putTeamMembership", () => {
  it("reports a membership GitHub left pending", async () => {
    api.putTeamMembership.mockResolvedValue({ pending: true });

    await expect(
      newClient().putTeamMembership({
        teamId: "7",
        login: "octocat",
        role: "member",
      })
    ).resolves.toEqual({ pending: true });
  });

  // GitHub documents a 403 for a team synced with an identity provider group.
  it("reports a 403 nothing else explains as the change refused, keeping GitHub's words", async () => {
    api.putTeamMembership.mockRejectedValue(failed("PUT", 403, "Forbidden"));

    const error = await newClient()
      .putTeamMembership({ teamId: "7", login: "octocat", role: "member" })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(TeamChangeRefusedError);
    expect((error as TeamChangeRefusedError).githubMessages).toEqual([
      "Forbidden",
    ]);
  });

  it.each([
    ["a missing permission", 403, "Resource not accessible by integration"],
    ["a suspended installation", 403, "This installation has been suspended"],
    ["a rate limit", 403, "You have exceeded a secondary rate limit."],
    ["a 404", 404, "Not Found"],
  ])("leaves %s as it is", async (_case, status, message) => {
    const error = failed("PUT", status, message);
    api.putTeamMembership.mockRejectedValue(error);

    await expect(
      newClient().putTeamMembership({
        teamId: "7",
        login: "octocat",
        role: "member",
      })
    ).rejects.toBe(error);
  });

  // Only the change itself is read that way.
  it("leaves a 403 from minting the token as it is", async () => {
    const error = failed("PUT", 403, "Forbidden");
    api.createInstallationToken.mockRejectedValue(error);

    await expect(
      newClient().putTeamMembership({
        teamId: "7",
        login: "octocat",
        role: "member",
      })
    ).rejects.toBe(error);
    expect(api.putTeamMembership).not.toHaveBeenCalled();
  });
});

describe("removeTeamMembership", () => {
  // So a revoke can run twice.
  it("succeeds when there was no membership to remove", async () => {
    api.deleteTeamMembership.mockRejectedValue(
      failed("DELETE", 404, "Not Found")
    );

    await expect(
      newClient().removeTeamMembership({ teamId: "7", login: "octocat" })
    ).resolves.toBeUndefined();
  });

  it("reports a 403 nothing else explains as the change refused", async () => {
    api.deleteTeamMembership.mockRejectedValue(
      failed("DELETE", 403, "Forbidden")
    );

    await expect(
      newClient().removeTeamMembership({ teamId: "7", login: "octocat" })
    ).rejects.toBeInstanceOf(TeamChangeRefusedError);
  });

  it("throws anything else", async () => {
    const error = failed("DELETE", 502, "boom");
    api.deleteTeamMembership.mockRejectedValue(error);

    await expect(
      newClient().removeTeamMembership({ teamId: "7", login: "octocat" })
    ).rejects.toBe(error);
  });
});

describe("fetchCurrentLogin", () => {
  it("returns the login the account has now", async () => {
    api.fetchAccountById.mockResolvedValue({
      id: 583231,
      login: "octocat-new",
    });

    await expect(newClient().fetchCurrentLogin("583231")).resolves.toBe(
      "octocat-new"
    );
    expect(api.fetchAccountById).toHaveBeenCalledWith("ghs_scoped", "583231");
  });

  it("returns null when the account is gone", async () => {
    api.fetchAccountById.mockResolvedValue(undefined);

    await expect(newClient().fetchCurrentLogin("583231")).resolves.toBeNull();
  });
});

describe("fetchAccount", () => {
  it("returns the account's GitHub user id as a string, and its login as GitHub spells it", async () => {
    api.fetchAccountByLogin.mockResolvedValue({ id: 583231, login: "OctoCat" });

    await expect(newClient().fetchAccount("octocat")).resolves.toEqual({
      githubUserId: "583231",
      login: "OctoCat",
    });
    expect(api.fetchAccountByLogin).toHaveBeenCalledWith(
      "ghs_scoped",
      "octocat"
    );
  });

  it("returns null when no account has the login", async () => {
    api.fetchAccountByLogin.mockResolvedValue(undefined);

    await expect(newClient().fetchAccount("octocat")).resolves.toBeNull();
  });
});

describe("fetchRepository", () => {
  it("returns the repository id as a string, and the name the repository has now", async () => {
    api.fetchRepository.mockResolvedValue({ id: 1296269, name: "api" });

    await expect(newClient().fetchRepository("old-api")).resolves.toEqual({
      repositoryId: "1296269",
      name: "api",
    });
    expect(api.fetchRepository).toHaveBeenCalledWith(
      "ghs_scoped",
      "acme",
      "old-api"
    );
  });

  it("returns null when the installation can't see the repository", async () => {
    api.fetchRepository.mockResolvedValue(undefined);

    await expect(newClient().fetchRepository("api")).resolves.toBeNull();
  });
});

describe("verifyAppJwt", () => {
  const status = (code: number) =>
    new GitHubError({
      method: "GET",
      path: "/app",
      status: code,
      githubMessages: ["x"],
    });

  it("is true when GitHub accepts the JWT", async () => {
    api.fetchAuthenticatedApp.mockResolvedValue(undefined);
    await expect(newClient().verifyAppJwt()).resolves.toBe(true);
    expect(api.fetchAuthenticatedApp).toHaveBeenCalledWith("signed-jwt");
  });

  it.each([401, 404])("is false on a %d", async (code) => {
    api.fetchAuthenticatedApp.mockRejectedValue(status(code));
    await expect(newClient().verifyAppJwt()).resolves.toBe(false);
  });

  it("throws anything else", async () => {
    api.fetchAuthenticatedApp.mockRejectedValue(status(502));
    await expect(newClient().verifyAppJwt()).rejects.toBeInstanceOf(
      GitHubError
    );
  });
});

describe("verifyOrgMembership", () => {
  it.each([
    ["active", true],
    ["pending", false],
    [undefined, false],
  ])("treats a %s membership as %s", async (state, member) => {
    api.fetchOrgMembershipState.mockResolvedValue(state);
    await expect(newClient().verifyOrgMembership("octocat")).resolves.toBe(
      member
    );
  });
});

describe("missingPermissions", () => {
  it("lets a higher level cover a lower one", () => {
    expect(
      missingPermissions(
        { administration: "admin", members: "write" },
        { administration: "write", members: "read", metadata: "read" }
      )
    ).toEqual(["metadata=read"]);
  });
});

describe("fetchBypassAllowances", () => {
  const BRANCH = { repo: "api", branch: "release/2026.10" };
  const ALLOWANCES = { users: ["hubot"], teams: ["release"], apps: [] };

  const rulesResponse = (
    patterns: string[],
    pageInfo: { endCursor: string | null; hasNextPage: boolean } = {
      endCursor: null,
      hasNextPage: false,
    }
  ) => ({
    repository: {
      branchProtectionRules: {
        pageInfo,
        nodes: patterns.map((pattern) => ({ pattern })),
      },
    },
  });

  beforeEach(() => {
    api.fetchBypassAllowances.mockResolvedValue(ALLOWANCES);
    api.githubGraphql.mockResolvedValue(
      rulesResponse(["main", "release/2026.10"])
    );
  });

  it("reads the list of a branch with a rule of its own, on one repo with administration: read", async () => {
    await expect(newClient().fetchBypassAllowances(BRANCH)).resolves.toEqual(
      ALLOWANCES
    );

    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: ["api"],
      permissions: { administration: "read" },
    });
    expect(api.fetchBypassAllowances).toHaveBeenCalledWith(
      "ghs_scoped",
      "acme",
      "api",
      "release/2026.10"
    );
    expect(api.githubGraphql).toHaveBeenCalledWith(
      "ghs_scoped",
      expect.stringContaining("branchProtectionRules"),
      { owner: "acme", repo: "api", cursor: null },
      expect.anything()
    );
  });

  it("walks every page of rules", async () => {
    api.githubGraphql
      .mockResolvedValueOnce(
        rulesResponse(["main"], { endCursor: "c1", hasNextPage: true })
      )
      .mockResolvedValueOnce(rulesResponse(["release/2026.10"]));

    await expect(newClient().fetchBypassAllowances(BRANCH)).resolves.toEqual(
      ALLOWANCES
    );
    expect(api.githubGraphql).toHaveBeenLastCalledWith(
      "ghs_scoped",
      expect.anything(),
      { owner: "acme", repo: "api", cursor: "c1" },
      expect.anything()
    );
  });

  // Changing a wildcard rule's list would change it for every branch it
  // matches.
  it("refuses a branch protected by a wildcard rule only", async () => {
    api.githubGraphql.mockResolvedValue(rulesResponse(["main", "release/*"]));

    await expect(
      newClient().fetchBypassAllowances(BRANCH)
    ).rejects.toBeInstanceOf(WildcardRuleError);
  });

  it("refuses a branch GitHub answers 404 for as not protected", async () => {
    api.fetchBypassAllowances.mockRejectedValue(
      new GitHubError({
        method: "GET",
        path: "/repos/acme/api/branches/release%2F2026.10/protection",
        status: 404,
        githubMessages: ["Branch not protected"],
      })
    );

    await expect(
      newClient().fetchBypassAllowances(BRANCH)
    ).rejects.toBeInstanceOf(BranchNotProtectedError);
    expect(api.githubGraphql).not.toHaveBeenCalled();
  });

  it("refuses a branch whose protection doesn't require reviews", async () => {
    api.fetchBypassAllowances.mockResolvedValue(undefined);

    await expect(
      newClient().fetchBypassAllowances(BRANCH)
    ).rejects.toBeInstanceOf(ReviewsNotRequiredError);
  });

  it("reports a repo GitHub won't show as not visible", async () => {
    api.githubGraphql.mockResolvedValue({ repository: null });

    await expect(
      newClient().fetchBypassAllowances(BRANCH)
    ).rejects.toBeInstanceOf(RepositoryNotVisibleError);
  });
});

describe("setBypassAllowances", () => {
  const BRANCH = { repo: "api", branch: "main" };
  const ALLOWANCES = { users: ["octocat"], teams: [], apps: ["deploy"] };

  it("writes all three lists on one repo with administration: write", async () => {
    api.patchBypassAllowances.mockResolvedValue(undefined);

    await newClient().setBypassAllowances({
      ...BRANCH,
      allowances: ALLOWANCES,
    });

    expect(api.createInstallationToken).toHaveBeenCalledWith(
      "signed-jwt",
      42,
      REPO_WRITE_SCOPE
    );
    expect(api.patchBypassAllowances).toHaveBeenCalledWith(
      "ghs_scoped",
      "acme",
      "api",
      "main",
      ALLOWANCES
    );
  });

  it("reports a 422 as the change refused, keeping GitHub's words", async () => {
    api.patchBypassAllowances.mockRejectedValue(
      new GitHubError({
        method: "PATCH",
        path: "/repos/acme/api/branches/main/protection/required_pull_request_reviews",
        status: 422,
        githubMessages: ["Validation Failed", "octocat can't push"],
      })
    );

    const error = await newClient()
      .setBypassAllowances({ ...BRANCH, allowances: ALLOWANCES })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(BypassChangeRefusedError);
    expect((error as BypassChangeRefusedError).githubMessages).toEqual([
      "Validation Failed",
      "octocat can't push",
    ]);
  });

  it("leaves any other failure as it is", async () => {
    const error = new GitHubError({
      method: "PATCH",
      path: "/repos/acme/api/branches/main/protection/required_pull_request_reviews",
      status: 404,
      githubMessages: ["Not Found"],
    });
    api.patchBypassAllowances.mockRejectedValue(error);

    await expect(
      newClient().setBypassAllowances({ ...BRANCH, allowances: ALLOWANCES })
    ).rejects.toBe(error);
  });
});
