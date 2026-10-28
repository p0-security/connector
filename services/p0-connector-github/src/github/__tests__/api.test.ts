import { ConnectorError } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  GitHubError,
  createInstallationToken,
  deleteCollaborator,
  deleteTeamMembership,
  fetchAccountById,
  fetchAccountByLogin,
  fetchAuthenticatedApp,
  fetchBypassAllowances,
  fetchOrgInstallation,
  fetchOrgMembershipState,
  fetchOrgTeamById,
  fetchOrgTeamBySlug,
  fetchRepository,
  fetchTeamMembershipState,
  githubGraphql,
  listOrgTeams,
  patchBypassAllowances,
  putCollaborator,
  putTeamMembership,
} from "../api.ts";

// Stub the global `fetch` so no real network call is made.
const mockedFetch = vi.fn<typeof fetch>();
vi.stubGlobal("fetch", mockedFetch);

const respond = (
  status: number,
  body?: unknown,
  headers: Record<string, string> = {}
) =>
  mockedFetch.mockResolvedValueOnce(
    new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers,
    })
  );

beforeEach(() => {
  mockedFetch.mockReset();
});

describe("putCollaborator", () => {
  it("PUTs the permission and reports a 204 as a plain role change", async () => {
    respond(204);

    await expect(
      putCollaborator("ghs_token", "acme", "api", "octocat", "push")
    ).resolves.toEqual({ invited: false, invitationId: undefined });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/repos/acme/api/collaborators/octocat",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ permission: "push" }),
        headers: expect.objectContaining({ Authorization: "Bearer ghs_token" }),
      })
    );
  });

  it("reports a 201 as an invitation, with its id", async () => {
    respond(201, { id: 99, invitee: { login: "octocat" } });

    await expect(
      putCollaborator("ghs_token", "acme", "api", "octocat", "push")
    ).resolves.toEqual({ invited: true, invitationId: 99 });
  });
});

describe("deleteCollaborator", () => {
  it("accepts an empty 204", async () => {
    respond(204);
    await expect(
      deleteCollaborator("ghs_token", "acme", "api", "octocat")
    ).resolves.toBeUndefined();
  });
});

// By the team's id, which a rename doesn't change.
describe("team memberships", () => {
  const URL =
    "https://api.github.com/organizations/1/team/7/memberships/octocat";

  it("PUTs the role and reports an active membership as set", async () => {
    respond(200, { role: "maintainer", state: "active" });

    await expect(
      putTeamMembership("ghs_token", 1, "7", "octocat", "maintainer")
    ).resolves.toEqual({ pending: false });
    expect(mockedFetch).toHaveBeenCalledWith(
      URL,
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ role: "maintainer" }),
        headers: expect.objectContaining({ Authorization: "Bearer ghs_token" }),
      })
    );
  });

  // GitHub invited someone outside the org instead of adding them. An answer
  // that doesn't say is read the same way, so the caller takes it back.
  it.each([
    ["a pending membership", { role: "member", state: "pending" }],
    ["a membership with no state", { role: "member" }],
    ["an empty answer", undefined],
  ])("reports %s as pending", async (_case, body) => {
    respond(200, body);

    await expect(
      putTeamMembership("ghs_token", 1, "7", "octocat", "member")
    ).resolves.toEqual({ pending: true });
  });

  it("DELETEs the membership, accepting an empty 204", async () => {
    respond(204);

    await expect(
      deleteTeamMembership("ghs_token", 1, "7", "octocat")
    ).resolves.toBeUndefined();
    expect(mockedFetch).toHaveBeenCalledWith(
      URL,
      expect.objectContaining({ method: "DELETE" })
    );
  });

  it("GETs a membership's state", async () => {
    respond(200, { role: "member", state: "active" });

    await expect(
      fetchTeamMembershipState("ghs_token", 1, "7", "octocat")
    ).resolves.toBe("active");
    expect(mockedFetch).toHaveBeenCalledWith(
      URL,
      expect.objectContaining({ method: "GET" })
    );
  });

  it("reports no membership as undefined", async () => {
    respond(404, { message: "Not Found" });

    await expect(
      fetchTeamMembershipState("ghs_token", 1, "7", "octocat")
    ).resolves.toBeUndefined();
  });
});

describe("teams", () => {
  const RESPONSE = {
    id: 7,
    node_id: "T_7",
    slug: "platform",
    name: "Platform",
  };
  const TEAM = { id: 7, nodeId: "T_7", slug: "platform", name: "Platform" };

  it("GETs one page of the org's teams, keeping each id, node id, slug and name", async () => {
    respond(200, [
      { ...RESPONSE, privacy: "closed" },
      {
        id: 8,
        node_id: "T_8",
        slug: "on-call",
        name: "On call",
        privacy: "secret",
      },
    ]);

    await expect(listOrgTeams("ghs_token", "acme", 2, 100)).resolves.toEqual([
      TEAM,
      { id: 8, nodeId: "T_8", slug: "on-call", name: "On call" },
    ]);
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/orgs/acme/teams?per_page=100&page=2",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("GETs the team that has a slug now", async () => {
    respond(200, { ...RESPONSE, privacy: "closed" });

    await expect(
      fetchOrgTeamBySlug("ghs_token", "acme", "platform")
    ).resolves.toEqual(TEAM);
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/orgs/acme/teams/platform",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("GETs a team by its id, returning its current slug", async () => {
    respond(200, { ...RESPONSE, slug: "platform-renamed" });

    await expect(fetchOrgTeamById("ghs_token", 1, "7")).resolves.toEqual({
      ...TEAM,
      slug: "platform-renamed",
    });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/organizations/1/team/7",
      expect.objectContaining({ method: "GET" })
    );
  });

  it.each([
    ["by slug", () => fetchOrgTeamBySlug("ghs_token", "acme", "platform")],
    ["by id", () => fetchOrgTeamById("ghs_token", 1, "7")],
  ])("returns undefined on a 404, %s", async (_case, get) => {
    respond(404, { message: "Not Found" });

    await expect(get()).resolves.toBeUndefined();
  });

  it("throws anything else", async () => {
    respond(502, { message: "boom" });

    await expect(fetchOrgTeamById("ghs_token", 1, "7")).rejects.toBeInstanceOf(
      GitHubError
    );
  });
});

describe("fetchAuthenticatedApp", () => {
  it("GETs the app with the App JWT", async () => {
    respond(200, { id: 1, slug: "p0-acme", name: "P0 Acme" });

    await expect(fetchAuthenticatedApp("signed-jwt")).resolves.toBeUndefined();
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/app",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer signed-jwt",
        }),
      })
    );
  });
});

describe("account lookups", () => {
  it("GETs an account by its id, returning its current login", async () => {
    respond(200, { id: 583231, login: "octocat-new", type: "User" });

    await expect(fetchAccountById("ghs_token", "583231")).resolves.toEqual({
      id: 583231,
      login: "octocat-new",
    });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/user/583231",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("GETs an account by its login", async () => {
    respond(200, { id: 583231, login: "OctoCat", type: "User" });

    await expect(fetchAccountByLogin("ghs_token", "octocat")).resolves.toEqual({
      id: 583231,
      login: "OctoCat",
    });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/users/octocat",
      expect.objectContaining({ method: "GET" })
    );
  });

  it.each([
    ["id", () => fetchAccountById("ghs_token", "583231")],
    ["login", () => fetchAccountByLogin("ghs_token", "octocat")],
  ])("returns undefined when no account has the %s", async (_case, get) => {
    respond(404, { message: "Not Found" });
    await expect(get()).resolves.toBeUndefined();
  });

  it("throws anything else", async () => {
    respond(502, { message: "Bad Gateway" });
    await expect(
      fetchAccountById("ghs_token", "583231")
    ).rejects.toBeInstanceOf(GitHubError);
  });
});

describe("fetchRepository", () => {
  it("GETs a repository, returning its id and current name", async () => {
    respond(200, { id: 1296269, name: "api", full_name: "acme/api" });

    await expect(
      fetchRepository("ghs_token", "acme", "old-api")
    ).resolves.toEqual({ id: 1296269, name: "api" });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/repos/acme/old-api",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("returns undefined on a 404", async () => {
    respond(404, { message: "Not Found" });
    await expect(
      fetchRepository("ghs_token", "acme", "api")
    ).resolves.toBeUndefined();
  });

  it("throws anything else", async () => {
    respond(502, { message: "Bad Gateway" });
    await expect(
      fetchRepository("ghs_token", "acme", "api")
    ).rejects.toBeInstanceOf(GitHubError);
  });
});

describe("path segments", () => {
  // `fetch` resolves dot segments, which would send the call somewhere else.
  it.each([
    ["login", "acme", "api", ".."],
    ["login", "acme", "api", "."],
    ["repo", "acme", "..", "octocat"],
    ["org", "..", "api", "octocat"],
  ])("refuses a dot segment as the %s", async (_field, org, repo, login) => {
    const error = await putCollaborator(
      "ghs_token",
      org,
      repo,
      login,
      "push"
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data.type).toBe("validation_error");
    expect(mockedFetch).not.toHaveBeenCalled();
  });

  it("encodes anything else", async () => {
    respond(204);
    await putCollaborator("ghs_token", "acme", "a b", "octocat", "push");
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/repos/acme/a%20b/collaborators/octocat",
      expect.anything()
    );
  });
});

describe("fetchOrgInstallation", () => {
  const installation = {
    id: 42,
    permissions: { administration: "write" },
    repository_selection: "all",
    target_id: 9919,
  };

  it("reports a live installation", async () => {
    respond(200, { ...installation, suspended_at: null });

    await expect(fetchOrgInstallation("signed-jwt", "acme")).resolves.toEqual({
      id: 42,
      permissions: { administration: "write" },
      repositorySelection: "all",
      suspended: false,
      orgId: 9919,
    });
  });

  it("reports a suspended installation", async () => {
    respond(200, { ...installation, suspended_at: "2026-09-01T00:00:00Z" });

    await expect(
      fetchOrgInstallation("signed-jwt", "acme")
    ).resolves.toMatchObject({ suspended: true });
  });

  // GitHub's by-id team routes need the org's id, so there's no guessing it.
  it("fails as unknown when GitHub doesn't name the installation's org", async () => {
    const { target_id: _, ...withoutOrg } = installation;
    respond(200, withoutOrg);

    const error = await fetchOrgInstallation("signed-jwt", "acme").catch(
      (e: unknown) => e
    );

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data.type).toBe("unknown");
  });
});

describe("fetchOrgInstallation: the org", () => {
  // GitHub's by-id team routes take it.
  it("reports the id of the org the app is installed on", async () => {
    respond(200, {
      id: 42,
      permissions: { metadata: "read" },
      repository_selection: "all",
      target_id: 9919,
    });

    await expect(fetchOrgInstallation("signed-jwt", "acme")).resolves.toEqual(
      expect.objectContaining({ orgId: 9919 })
    );
  });
});

describe("createInstallationToken", () => {
  it("POSTs the scope with the App JWT and returns the token", async () => {
    respond(201, { token: "ghs_scoped", expires_at: "2026-10-01T00:00:00Z" });

    await expect(
      createInstallationToken("signed-jwt", 42, {
        repositories: ["api"],
        permissions: { administration: "write" },
      })
    ).resolves.toBe("ghs_scoped");
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/app/installations/42/access_tokens",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          repositories: ["api"],
          permissions: { administration: "write" },
        }),
        headers: expect.objectContaining({
          Authorization: "Bearer signed-jwt",
        }),
      })
    );
  });
});

describe("fetchOrgMembershipState", () => {
  it("returns undefined for a non-member", async () => {
    respond(404, { message: "Not Found" });
    await expect(
      fetchOrgMembershipState("ghs_token", "acme", "octocat")
    ).resolves.toBeUndefined();
  });
});

describe("errors", () => {
  it("carries the status, GitHub's messages and the accepted permissions, but not the token", async () => {
    respond(
      422,
      {
        message: "Validation Failed",
        errors: [
          { code: "custom", message: "Cannot assign member permission" },
        ],
      },
      { "X-Accepted-GitHub-Permissions": "administration=write" }
    );

    const error = await putCollaborator(
      "SECRET_TOKEN",
      "acme",
      "api",
      "octocat",
      "pull"
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(GitHubError);
    const { status, githubMessages, acceptedPermissions, message } =
      error as GitHubError;
    expect(status).toBe(422);
    expect(githubMessages).toEqual([
      "Validation Failed",
      "Cannot assign member permission",
    ]);
    expect(acceptedPermissions).toBe("administration=write");
    expect(message).not.toContain("SECRET_TOKEN");
    expect(JSON.stringify(error)).not.toContain("SECRET_TOKEN");
  });

  it("keeps errors[] entries that are plain strings", async () => {
    respond(422, {
      message: "Validation Failed",
      errors: ["Cannot assign member permission of read"],
    });

    const error = await putCollaborator(
      "ghs_token",
      "acme",
      "api",
      "octocat",
      "pull"
    ).catch((e: unknown) => e);

    expect((error as GitHubError).githubMessages).toEqual([
      "Validation Failed",
      "Cannot assign member permission of read",
    ]);
  });

  it("reports a network failure with no status", async () => {
    mockedFetch.mockRejectedValueOnce(new TypeError("fetch failed"));

    const error = await deleteCollaborator(
      "ghs_token",
      "acme",
      "api",
      "octocat"
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(GitHubError);
    expect((error as GitHubError).status).toBeUndefined();
  });
});

describe("githubGraphql", () => {
  it("returns the data", async () => {
    respond(200, { data: { viewer: { login: "octocat" } } });

    await expect(
      githubGraphql(
        "ghs_token",
        "query { viewer { login } }",
        {},
        z.object({ viewer: z.object({ login: z.string() }) })
      )
    ).resolves.toEqual({ viewer: { login: "octocat" } });
  });

  it("fails as unknown when the data doesn't match the query's schema", async () => {
    respond(200, { data: { viewer: null } });

    const error = await githubGraphql(
      "ghs_token",
      "query { viewer { login } }",
      {},
      z.object({ viewer: z.object({ login: z.string() }) })
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data.type).toBe("unknown");
  });

  it("throws on a GraphQL error, typed by its status and path", async () => {
    respond(200, {
      data: { repository: null },
      errors: [
        {
          type: "NOT_FOUND",
          path: ["repository"],
          message:
            "Could not resolve to a Repository with the name 'acme/api'.",
        },
      ],
    });

    const error = await githubGraphql(
      "ghs_token",
      "query",
      {},
      z.unknown()
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(GitHubError);
    expect((error as GitHubError).status).toBe(404);
    expect((error as GitHubError).graphqlPath).toBe("repository");
  });

  // Reported as the 200 it arrived in, it would map to `unknown`.
  it.each([
    [
      "no type",
      { message: "Something went wrong while executing your query." },
    ],
    ["an unknown type", { type: "INTERNAL", message: "Internal error" }],
  ])(
    "reports a GraphQL error with %s as a bad gateway",
    async (_case, graphqlError) => {
      respond(200, { data: null, errors: [graphqlError] });

      const error = await githubGraphql(
        "ghs_token",
        "query",
        {},
        z.unknown()
      ).catch((e: unknown) => e);

      expect(error).toBeInstanceOf(GitHubError);
      expect((error as GitHubError).status).toBe(502);
      expect((error as GitHubError).githubMessages).toEqual([
        graphqlError.message,
      ]);
    }
  );
});

describe("fetchBypassAllowances", () => {
  it("reads the logins and slugs, encoding a branch with a slash as one segment", async () => {
    respond(200, {
      required_pull_request_reviews: {
        required_approving_review_count: 1,
        bypass_pull_request_allowances: {
          users: [{ login: "hubot", id: 1 }],
          teams: [{ slug: "release", id: 2 }],
          apps: [{ slug: "deploy", id: 3 }],
        },
      },
      enforce_admins: { enabled: false },
    });

    await expect(
      fetchBypassAllowances("ghs_token", "acme", "api", "release/2026.10")
    ).resolves.toEqual({
      users: ["hubot"],
      teams: ["release"],
      apps: ["deploy"],
    });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/repos/acme/api/branches/release%2F2026.10/protection",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("reads required reviews with no bypass list as empty lists", async () => {
    respond(200, { required_pull_request_reviews: {} });

    await expect(
      fetchBypassAllowances("ghs_token", "acme", "api", "main")
    ).resolves.toEqual({ users: [], teams: [], apps: [] });
  });

  it("reads protection without required reviews as undefined", async () => {
    respond(200, { enforce_admins: { enabled: true } });

    await expect(
      fetchBypassAllowances("ghs_token", "acme", "api", "main")
    ).resolves.toBeUndefined();
  });

  it("refuses the branch `..`, which would change the URL", async () => {
    await expect(
      fetchBypassAllowances("ghs_token", "acme", "api", "..")
    ).rejects.toBeInstanceOf(ConnectorError);
    expect(mockedFetch).not.toHaveBeenCalled();
  });
});

describe("patchBypassAllowances", () => {
  it("sends the three lists alone, so other review settings stay", async () => {
    respond(200, {});
    const allowances = { users: ["octocat"], teams: [], apps: ["deploy"] };

    await patchBypassAllowances("ghs_token", "acme", "api", "main", allowances);

    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/repos/acme/api/branches/main/protection/required_pull_request_reviews",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({ bypass_pull_request_allowances: allowances }),
      })
    );
  });
});
