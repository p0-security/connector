import { ConnectorError } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  GitHubError,
  createInstallationToken,
  deleteCollaborator,
  deleteInvitation,
  getAccountById,
  getAccountByLogin,
  getAuthenticatedApp,
  getOrgInstallation,
  getOrgMembershipState,
  getRepository,
  githubGraphql,
  listRepositoryInvitations,
  putCollaborator,
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

describe("deleteInvitation", () => {
  it("DELETEs the repo invitation by id", async () => {
    respond(204);

    await expect(
      deleteInvitation("ghs_token", "acme", "api", 99)
    ).resolves.toBeUndefined();
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/repos/acme/api/invitations/99",
      expect.objectContaining({
        method: "DELETE",
        headers: expect.objectContaining({ Authorization: "Bearer ghs_token" }),
      })
    );
  });
});

describe("listRepositoryInvitations", () => {
  it("GETs one page of the repo's invitations", async () => {
    const page = [
      {
        id: 99,
        invitee: { login: "octocat" },
        inviter: { login: "p0-acme[bot]" },
      },
    ];
    respond(200, page);

    await expect(
      listRepositoryInvitations("ghs_token", "acme", "api", 2, 100)
    ).resolves.toEqual(page);
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/repos/acme/api/invitations?per_page=100&page=2",
      expect.objectContaining({ method: "GET" })
    );
  });
});

describe("getAuthenticatedApp", () => {
  it("returns the app's slug", async () => {
    respond(200, { id: 1, slug: "p0-acme", name: "P0 Acme" });

    await expect(getAuthenticatedApp("signed-jwt")).resolves.toEqual({
      slug: "p0-acme",
    });
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

  it("reports a missing slug as undefined", async () => {
    respond(200, { id: 1 });

    await expect(getAuthenticatedApp("signed-jwt")).resolves.toEqual({
      slug: undefined,
    });
  });
});

describe("account lookups", () => {
  it("GETs an account by its id, returning its current login", async () => {
    respond(200, { id: 583231, login: "octocat-new", type: "User" });

    await expect(getAccountById("ghs_token", "583231")).resolves.toEqual({
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

    await expect(getAccountByLogin("ghs_token", "octocat")).resolves.toEqual({
      id: 583231,
      login: "OctoCat",
    });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/users/octocat",
      expect.objectContaining({ method: "GET" })
    );
  });

  it.each([
    ["id", () => getAccountById("ghs_token", "583231")],
    ["login", () => getAccountByLogin("ghs_token", "octocat")],
  ])("returns undefined when no account has the %s", async (_case, get) => {
    respond(404, { message: "Not Found" });
    await expect(get()).resolves.toBeUndefined();
  });

  it("throws anything else", async () => {
    respond(502, { message: "Bad Gateway" });
    await expect(getAccountById("ghs_token", "583231")).rejects.toBeInstanceOf(
      GitHubError
    );
  });
});

describe("getRepository", () => {
  it("GETs a repository, returning its id and current name", async () => {
    respond(200, { id: 1296269, name: "api", full_name: "acme/api" });

    await expect(
      getRepository("ghs_token", "acme", "old-api")
    ).resolves.toEqual({ id: 1296269, name: "api" });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/repos/acme/old-api",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("returns undefined on a 404", async () => {
    respond(404, { message: "Not Found" });
    await expect(
      getRepository("ghs_token", "acme", "api")
    ).resolves.toBeUndefined();
  });

  it("throws anything else", async () => {
    respond(502, { message: "Bad Gateway" });
    await expect(
      getRepository("ghs_token", "acme", "api")
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

describe("getOrgInstallation", () => {
  const installation = {
    id: 42,
    permissions: { administration: "write" },
    repository_selection: "all",
  };

  it("reports a live installation", async () => {
    respond(200, { ...installation, suspended_at: null });

    await expect(getOrgInstallation("signed-jwt", "acme")).resolves.toEqual({
      id: 42,
      permissions: { administration: "write" },
      repositorySelection: "all",
      suspended: false,
    });
  });

  it("reports a suspended installation", async () => {
    respond(200, { ...installation, suspended_at: "2026-09-01T00:00:00Z" });

    await expect(
      getOrgInstallation("signed-jwt", "acme")
    ).resolves.toMatchObject({ suspended: true });
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

describe("getOrgMembershipState", () => {
  it("returns undefined for a non-member", async () => {
    respond(404, { message: "Not Found" });
    await expect(
      getOrgMembershipState("ghs_token", "acme", "octocat")
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
      githubGraphql("ghs_token", "query { viewer { login } }", {})
    ).resolves.toEqual({ viewer: { login: "octocat" } });
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

    const error = await githubGraphql("ghs_token", "query", {}).catch(
      (e: unknown) => e
    );

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

      const error = await githubGraphql("ghs_token", "query", {}).catch(
        (e: unknown) => e
      );

      expect(error).toBeInstanceOf(GitHubError);
      expect((error as GitHubError).status).toBe(502);
      expect((error as GitHubError).githubMessages).toEqual([
        graphqlError.message,
      ]);
    }
  );
});
