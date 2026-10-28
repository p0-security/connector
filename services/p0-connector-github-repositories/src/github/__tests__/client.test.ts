import { beforeEach, describe, expect, it, vi } from "vitest";

import type * as apiModule from "../api.ts";
import { GitHubError, type Installation } from "../api.ts";
import { missingPermissions, newGitHubClient } from "../client.ts";
import {
  AppNotInstalledError,
  InstallationSuspendedError,
  MissingPermissionsError,
  RepositoryNotVisibleError,
} from "../errors.ts";

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factories run.
const api = vi.hoisted(() => ({
  createInstallationToken: vi.fn(),
  getAuthenticatedApp: vi.fn(),
  getOrgInstallation: vi.fn(),
  githubGraphql: vi.fn(),
  listInstallationRepositories: vi.fn(),
  getOrgMembershipState: vi.fn(),
  putCollaborator: vi.fn(),
  deleteCollaborator: vi.fn(),
  deleteInvitation: vi.fn(),
  listRepositoryInvitations: vi.fn(),
  getAccountById: vi.fn(),
  getAccountByLogin: vi.fn(),
  getRepository: vi.fn(),
}));

const createAppJwt = vi.hoisted(() => vi.fn(() => "signed-jwt"));
vi.mock("../jwt.ts", () => ({ createAppJwt }));
vi.mock("../api.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof apiModule>()),
  ...api,
}));

const INSTALLATION: Installation = {
  id: 42,
  permissions: {
    administration: "write",
    metadata: "read",
    members: "read",
    organization_custom_roles: "read",
  },
  repositorySelection: "selected",
  suspended: false,
};

const REPO_WRITE_SCOPE = {
  repositories: ["api"],
  permissions: { administration: "write" },
};

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
  api.getOrgInstallation.mockResolvedValue(INSTALLATION);
  api.createInstallationToken.mockResolvedValue("ghs_scoped");
});

describe("installation tokens", () => {
  it("finds the installation from the org, once per client", async () => {
    const client = newClient();
    api.githubGraphql.mockResolvedValue(directRoleResponse([]));

    await client.readDirectRole("api", "octocat");
    await client.readDirectRole("api", "octocat");

    expect(api.getOrgInstallation).toHaveBeenCalledTimes(1);
    expect(api.getOrgInstallation).toHaveBeenCalledWith("signed-jwt", "acme");
  });

  it("reports an org with no installation as not installed", async () => {
    api.getOrgInstallation.mockRejectedValue(
      new GitHubError({
        method: "GET",
        path: "/orgs/acme/installation",
        status: 404,
        githubMessages: ["Not Found"],
      })
    );

    await expect(newClient().findInstallation()).rejects.toBeInstanceOf(
      AppNotInstalledError
    );
  });

  // A JWT expires minutes after it's signed, and a client can outlive that.
  it("signs a fresh App JWT for every call that needs one", async () => {
    const client = newClient();
    api.githubGraphql.mockResolvedValue(directRoleResponse([]));
    createAppJwt
      .mockReturnValueOnce("jwt-1")
      .mockReturnValueOnce("jwt-2")
      .mockReturnValueOnce("jwt-3");

    await client.readDirectRole("api", "octocat");
    await client.readDirectRole("api", "octocat");

    expect(api.getOrgInstallation).toHaveBeenCalledWith("jwt-1", "acme");
    expect(api.createInstallationToken.mock.calls.map(([jwt]) => jwt)).toEqual([
      "jwt-2",
      "jwt-3",
    ]);
    expect(createAppJwt).toHaveBeenCalledWith({
      appId: "123456",
      privateKey: "PEM",
    });
  });

  it("mints a fresh token per call", async () => {
    const client = newClient();
    api.githubGraphql.mockResolvedValue(directRoleResponse([]));

    await client.readDirectRole("api", "octocat");
    await client.readDirectRole("api", "octocat");

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

  it("scopes the invitation sequence to one repo with administration: write, minting once", async () => {
    api.getAuthenticatedApp.mockResolvedValue({ slug: "p0-acme" });
    api.listRepositoryInvitations.mockResolvedValue([]);

    const invitations = await newClient().repositoryInvitations("api");
    await invitations.cancel(99);
    await invitations.findInvitationIds({
      invitee: "octocat",
      inviter: "p0-acme[bot]",
    });
    await invitations.cancel(100);

    expect(api.createInstallationToken).toHaveBeenCalledTimes(1);
    expect(api.createInstallationToken).toHaveBeenCalledWith(
      "signed-jwt",
      42,
      REPO_WRITE_SCOPE
    );
    expect(api.deleteInvitation).toHaveBeenNthCalledWith(
      1,
      "ghs_scoped",
      "acme",
      "api",
      99
    );
    expect(api.deleteInvitation).toHaveBeenNthCalledWith(
      2,
      "ghs_scoped",
      "acme",
      "api",
      100
    );
  });

  // The user endpoints are public, but a token has to ask for something.
  it("scopes resolving a GitHub user id to metadata: read, naming no repos", async () => {
    api.getAccountById.mockResolvedValue({ id: 583231, login: "octocat" });

    await newClient().currentLogin("583231");

    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: undefined,
      permissions: { metadata: "read" },
    });
  });

  it("scopes the account listing to metadata: read, naming no repos", async () => {
    api.getAccountByLogin.mockResolvedValue({ id: 583231, login: "octocat" });

    await newClient().findAccount("octocat");

    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: undefined,
      permissions: { metadata: "read" },
    });
  });

  // It may be given a renamed repository's old name, which can't scope a token.
  it("scopes a repository id lookup to metadata: read, naming no repos", async () => {
    api.getRepository.mockResolvedValue({ id: 1296269, name: "api" });

    await newClient().findRepository("old-api");

    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: undefined,
      permissions: { metadata: "read" },
    });
  });

  it("scopes a role read to one repo with metadata: read", async () => {
    api.githubGraphql.mockResolvedValue(directRoleResponse([]));

    await newClient().readDirectRole("api", "octocat");

    expect(api.createInstallationToken).toHaveBeenCalledWith("signed-jwt", 42, {
      repositories: ["api"],
      permissions: { metadata: "read" },
    });
  });

  // Naming no repositories means the whole selection, so this token also
  // reads metadata on every repo in it.
  it("scopes an org read to one org permission, naming no repos", async () => {
    api.getOrgMembershipState.mockResolvedValue("active");

    await newClient().isMember("octocat");

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
    api.getOrgInstallation.mockResolvedValue({
      ...INSTALLATION,
      suspended: true,
    });

    await expect(
      newClient().putRole("api", "octocat", "push")
    ).rejects.toBeInstanceOf(InstallationSuspendedError);
    expect(api.createInstallationToken).not.toHaveBeenCalled();
  });

  it("refuses to mint a token the installation wasn't granted, naming the permission", async () => {
    api.getOrgInstallation.mockResolvedValue({
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

describe("readDirectRole", () => {
  it("returns the Repository source's role in PUT form", async () => {
    api.githubGraphql.mockResolvedValue(
      directRoleResponse([
        { roleName: "maintain", source: { __typename: "Team" } },
        { roleName: "write", source: { __typename: "Repository" } },
        { roleName: "read", source: { __typename: "Organization" } },
      ])
    );

    await expect(newClient().readDirectRole("api", "octocat")).resolves.toBe(
      "push"
    );
    expect(api.githubGraphql).toHaveBeenCalledWith(
      "ghs_scoped",
      expect.stringContaining("collaborators(affiliation: DIRECT"),
      { owner: "acme", repo: "api", login: "octocat" }
    );
  });

  it("normalises Triage Plus in display form", async () => {
    api.githubGraphql.mockResolvedValue(
      directRoleResponse([
        { roleName: "Triage Plus", source: { __typename: "Repository" } },
      ])
    );

    await expect(newClient().readDirectRole("api", "octocat")).resolves.toBe(
      "triage_plus"
    );
  });

  it("keeps a custom role's name", async () => {
    api.githubGraphql.mockResolvedValue(
      directRoleResponse([
        { roleName: "Labeler", source: { __typename: "Repository" } },
      ])
    );

    await expect(newClient().readDirectRole("api", "octocat")).resolves.toBe(
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
      newClient().readDirectRole("api", "octocat")
    ).resolves.toBeNull();
  });

  it("returns null for someone with no direct role", async () => {
    api.githubGraphql.mockResolvedValue(directRoleResponse([]));
    await expect(
      newClient().readDirectRole("api", "octocat")
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

    await expect(newClient().readDirectRole("api", "octocat")).rejects.toEqual(
      new RepositoryNotVisibleError("api")
    );
  });

  // Reading nothing as "no direct role" would let a revoke report success.
  it("fails when GitHub returns no collaborators connection", async () => {
    api.githubGraphql.mockResolvedValue({
      repository: { collaborators: null },
    });

    const error = await newClient()
      .readDirectRole("api", "octocat")
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
      { org: "acme", cursor: "c1" }
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

describe("appBotLogin", () => {
  it("names the app's bot user from its slug, reading it once per client", async () => {
    api.getAuthenticatedApp.mockResolvedValue({ slug: "p0-acme" });
    const client = newClient();

    await expect(client.appBotLogin()).resolves.toBe("p0-acme[bot]");
    await expect(client.appBotLogin()).resolves.toBe("p0-acme[bot]");
    expect(api.getAuthenticatedApp).toHaveBeenCalledTimes(1);
    expect(api.getAuthenticatedApp).toHaveBeenCalledWith("signed-jwt");
  });

  it("fails rather than guess when GitHub doesn't name the app", async () => {
    api.getAuthenticatedApp.mockResolvedValue({ slug: undefined });

    await expect(newClient().appBotLogin()).rejects.toThrow(
      "GitHub didn't return the GitHub App's slug"
    );
  });
});

describe("findInvitationIds", () => {
  const APP_INVITATIONS = { invitee: "octocat", inviter: "p0-acme[bot]" };

  const invitation = (
    id: number,
    invitee: string | null,
    inviter: string | null = "p0-acme[bot]"
  ) => ({
    id,
    invitee: invitee === null ? null : { login: invitee },
    inviter: inviter === null ? null : { login: inviter },
  });

  it("pages through the repo's invitations, matching the login ignoring case", async () => {
    api.listRepositoryInvitations
      .mockResolvedValueOnce([
        invitation(1, "Octocat"),
        ...Array.from({ length: 99 }, (_, i) => invitation(100 + i, "hubot")),
      ])
      .mockResolvedValueOnce([invitation(2, null), invitation(3, "octocat")]);

    const invitations = await newClient().repositoryInvitations("api");

    await expect(
      invitations.findInvitationIds(APP_INVITATIONS)
    ).resolves.toEqual([1, 3]);
    expect(api.listRepositoryInvitations).toHaveBeenNthCalledWith(
      2,
      "ghs_scoped",
      "acme",
      "api",
      2,
      100
    );
  });

  // P0 never cancels an invitation a person sent.
  it("leaves out invitations the app didn't send", async () => {
    api.listRepositoryInvitations.mockResolvedValue([
      invitation(1, "octocat", "an-admin"),
      invitation(2, "octocat", null),
      invitation(3, "octocat", "other-app[bot]"),
      invitation(4, "octocat", "P0-Acme[bot]"),
    ]);

    const invitations = await newClient().repositoryInvitations("api");

    await expect(
      invitations.findInvitationIds(APP_INVITATIONS)
    ).resolves.toEqual([4]);
  });
});

describe("currentLogin", () => {
  it("returns the login the account has now", async () => {
    api.getAccountById.mockResolvedValue({ id: 583231, login: "octocat-new" });

    await expect(newClient().currentLogin("583231")).resolves.toBe(
      "octocat-new"
    );
    expect(api.getAccountById).toHaveBeenCalledWith("ghs_scoped", "583231");
  });

  it("returns null when the account is gone", async () => {
    api.getAccountById.mockResolvedValue(undefined);

    await expect(newClient().currentLogin("583231")).resolves.toBeNull();
  });
});

describe("findAccount", () => {
  it("returns the account's GitHub user id as a string, and its login as GitHub spells it", async () => {
    api.getAccountByLogin.mockResolvedValue({ id: 583231, login: "OctoCat" });

    await expect(newClient().findAccount("octocat")).resolves.toEqual({
      githubUserId: "583231",
      login: "OctoCat",
    });
    expect(api.getAccountByLogin).toHaveBeenCalledWith("ghs_scoped", "octocat");
  });

  it("returns null when no account has the login", async () => {
    api.getAccountByLogin.mockResolvedValue(undefined);

    await expect(newClient().findAccount("octocat")).resolves.toBeNull();
  });
});

describe("findRepository", () => {
  it("returns the repository id as a string, and the name the repository has now", async () => {
    api.getRepository.mockResolvedValue({ id: 1296269, name: "api" });

    await expect(newClient().findRepository("old-api")).resolves.toEqual({
      repositoryId: "1296269",
      name: "api",
    });
    expect(api.getRepository).toHaveBeenCalledWith(
      "ghs_scoped",
      "acme",
      "old-api"
    );
  });

  it("returns null when the installation can't see the repository", async () => {
    api.getRepository.mockResolvedValue(undefined);

    await expect(newClient().findRepository("api")).resolves.toBeNull();
  });
});

describe("isAppJwtAccepted", () => {
  const status = (code: number) =>
    new GitHubError({
      method: "GET",
      path: "/app",
      status: code,
      githubMessages: ["x"],
    });

  it("is true when GitHub accepts the JWT", async () => {
    api.getAuthenticatedApp.mockResolvedValue({ slug: "p0-acme" });
    await expect(newClient().isAppJwtAccepted()).resolves.toBe(true);
    expect(api.getAuthenticatedApp).toHaveBeenCalledWith("signed-jwt");
  });

  it.each([401, 404])("is false on a %d", async (code) => {
    api.getAuthenticatedApp.mockRejectedValue(status(code));
    await expect(newClient().isAppJwtAccepted()).resolves.toBe(false);
  });

  it("throws anything else", async () => {
    api.getAuthenticatedApp.mockRejectedValue(status(502));
    await expect(newClient().isAppJwtAccepted()).rejects.toBeInstanceOf(
      GitHubError
    );
  });
});

describe("isMember", () => {
  it.each([
    ["active", true],
    ["pending", false],
    [undefined, false],
  ])("treats a %s membership as %s", async (state, member) => {
    api.getOrgMembershipState.mockResolvedValue(state);
    await expect(newClient().isMember("octocat")).resolves.toBe(member);
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
