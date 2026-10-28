import { ConnectorError } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  createServiceAccountToken,
  deleteServiceAccount,
  findServiceAccountId,
  findServiceAccountTokenId,
  listGroupProjects,
  setProjectMember,
} from "../gitlab-api.ts";

const mockedFetch = vi.fn();
vi.stubGlobal("fetch", mockedFetch);

const auth = { token: "admin-token" };

const jsonResponse = (
  data: unknown,
  init?: {
    ok?: boolean;
    status?: number;
    statusText?: string;
    nextPage?: string;
  }
) => ({
  ok: init?.ok ?? true,
  status: init?.status ?? 200,
  statusText: init?.statusText ?? "OK",
  headers: new Headers(init?.nextPage ? { "x-next-page": init.nextPage } : {}),
  json: async () => data,
});

const notFound = () =>
  jsonResponse(
    { message: "404 Not found" },
    { ok: false, status: 404, statusText: "Not Found" }
  );

beforeEach(() => {
  mockedFetch.mockReset();
});

describe("createServiceAccountToken", () => {
  it("POSTs the scopes with the admin token and maps the response", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({ id: 7, token: "glpat-x" }, { status: 201 })
    );

    await expect(
      createServiceAccountToken(auth, {
        groupId: "42",
        userId: 9,
        name: "P0 grant",
        scopes: ["mcp"],
      })
    ).resolves.toEqual({ id: 7, token: "glpat-x" });

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe(
      "https://gitlab.com/api/v4/groups/42/service_accounts/9/personal_access_tokens"
    );
    expect(init).toEqual(
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ "PRIVATE-TOKEN": "admin-token" }),
        body: JSON.stringify({ name: "P0 grant", scopes: ["mcp"] }),
      })
    );
  });

  it("surfaces GitLab's message but not the token", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse(
        { message: "403 Forbidden" },
        { ok: false, status: 403, statusText: "Forbidden" }
      )
    );

    const error = await createServiceAccountToken(auth, {
      groupId: "42",
      userId: 9,
      name: "P0 grant",
      scopes: ["mcp"],
    }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).message).toContain("403 Forbidden");
    expect(JSON.stringify(error)).not.toContain("admin-token");
  });
});

describe("findServiceAccountId", () => {
  it("returns the id of the group's service account", async () => {
    mockedFetch
      .mockResolvedValueOnce(jsonResponse([{ id: 9 }]))
      .mockResolvedValueOnce(jsonResponse({ id: 9 }));

    await expect(
      findServiceAccountId(auth, { groupId: "42", username: "p0-grant-a" })
    ).resolves.toBe(9);
    expect(mockedFetch.mock.calls[0][0]).toBe(
      "https://gitlab.com/api/v4/users?username=p0-grant-a"
    );
    expect(mockedFetch.mock.calls[1][0]).toBe(
      "https://gitlab.com/api/v4/groups/42/service_accounts/9"
    );
  });

  it("ignores a user of the same name that is not the group's service account", async () => {
    mockedFetch
      .mockResolvedValueOnce(jsonResponse([{ id: 9 }]))
      .mockResolvedValueOnce(notFound());

    await expect(
      findServiceAccountId(auth, { groupId: "42", username: "p0-grant-a" })
    ).resolves.toBeUndefined();
  });

  it("returns undefined when no user has the name", async () => {
    mockedFetch.mockResolvedValueOnce(jsonResponse([]));

    await expect(
      findServiceAccountId(auth, { groupId: "42", username: "p0-grant-a" })
    ).resolves.toBeUndefined();
  });
});

describe("findServiceAccountTokenId", () => {
  it("matches the exact name across pages", async () => {
    mockedFetch
      .mockResolvedValueOnce(
        jsonResponse([{ id: 1, name: "P0 grant-2" }], { nextPage: "2" })
      )
      .mockResolvedValueOnce(jsonResponse([{ id: 2, name: "P0 grant" }]));

    await expect(
      findServiceAccountTokenId(auth, {
        groupId: "42",
        userId: 9,
        name: "P0 grant",
      })
    ).resolves.toBe(2);
    expect(mockedFetch.mock.calls[1][0]).toContain("page=2");
  });

  it("fails when two tokens have the name", async () => {
    mockedFetch.mockResolvedValueOnce(
      jsonResponse([
        { id: 1, name: "P0 grant" },
        { id: 2, name: "P0 grant" },
      ])
    );

    await expect(
      findServiceAccountTokenId(auth, {
        groupId: "42",
        userId: 9,
        name: "P0 grant",
      })
    ).rejects.toThrow(ConnectorError);
  });
});

describe("deleteServiceAccount", () => {
  it("hard-deletes the service account", async () => {
    mockedFetch.mockResolvedValue(jsonResponse(undefined, { status: 204 }));

    await deleteServiceAccount(auth, { groupId: "42", userId: 9 });

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe(
      "https://gitlab.com/api/v4/groups/42/service_accounts/9?hard_delete=true"
    );
    expect(init).toEqual(expect.objectContaining({ method: "DELETE" }));
  });

  it("treats a service account that is gone as deleted", async () => {
    mockedFetch.mockResolvedValue(notFound());

    await expect(
      deleteServiceAccount(auth, { groupId: "42", userId: 9 })
    ).resolves.toBeUndefined();
  });
});

describe("setProjectMember", () => {
  it("adds a user that is not a member", async () => {
    mockedFetch
      .mockResolvedValueOnce(notFound())
      .mockResolvedValueOnce(jsonResponse({}, { status: 201 }));

    await setProjectMember(auth, { projectId: 5, userId: 9, accessLevel: 30 });

    const [url, init] = mockedFetch.mock.calls[1];
    expect(url).toBe("https://gitlab.com/api/v4/projects/5/members");
    expect(init).toEqual(
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ user_id: 9, access_level: 30 }),
      })
    );
  });

  it("changes the role of a member", async () => {
    mockedFetch
      .mockResolvedValueOnce(jsonResponse({ access_level: 20 }))
      .mockResolvedValueOnce(jsonResponse({}));

    await setProjectMember(auth, { projectId: 5, userId: 9, accessLevel: 30 });

    const [url, init] = mockedFetch.mock.calls[1];
    expect(url).toBe("https://gitlab.com/api/v4/projects/5/members/9");
    expect(init).toEqual(expect.objectContaining({ method: "PUT" }));
  });

  it("does nothing when the role is already right", async () => {
    mockedFetch.mockResolvedValueOnce(jsonResponse({ access_level: 30 }));

    await setProjectMember(auth, { projectId: 5, userId: 9, accessLevel: 30 });

    expect(mockedFetch).toHaveBeenCalledTimes(1);
  });
});

describe("listGroupProjects", () => {
  it("lists the projects of the group and its subgroups", async () => {
    mockedFetch.mockResolvedValueOnce(
      jsonResponse([{ id: 5, path_with_namespace: "g/sub/app" }])
    );

    await expect(listGroupProjects(auth, "g")).resolves.toEqual([
      { id: 5, pathWithNamespace: "g/sub/app" },
    ]);
    expect(mockedFetch.mock.calls[0][0]).toContain("include_subgroups=true");
  });
});
