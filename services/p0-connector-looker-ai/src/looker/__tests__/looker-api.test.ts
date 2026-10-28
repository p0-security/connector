import type * as connector from "@p0security/connector";
import { ConnectorError } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  createApiKey,
  createContentAccess,
  createModelSet,
  createPermissionSet,
  createRole,
  createServiceAccount,
  deleteContentAccess,
  deleteServiceAccount,
  findFolder,
  findModelSet,
  findPermissionSet,
  findRole,
  listContentAccess,
  listDirectRoleIds,
  listGroupsWithRoles,
  listModels,
  listPermissionParents,
  listServiceAccountIds,
  listServiceAccounts,
  login,
  logout,
  setUserName,
  setUserRoles,
  updateContentAccess,
} from "../looker-api.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const logged = vi.hoisted(() => ({ warn: vi.fn(), error: vi.fn() }));

// The client's own logger records its warnings and errors, so a test can read
// the level of each line.
vi.mock("@p0security/connector", async (importOriginal) => {
  const actual = await importOriginal<typeof connector>();
  return {
    ...actual,
    createLogger: () => Object.assign(actual.createLogger(), logged),
  };
});

const mockedFetch = vi.fn();
vi.stubGlobal("fetch", mockedFetch);

const BASE_URL = "https://example.looker.app";

const adminKey = { client_id: "admin-id", client_secret: "admin-secret" };

const session = { baseUrl: BASE_URL, accessToken: "admin-token" };

const jsonResponse = (
  data: unknown,
  init?: { ok?: boolean; status?: number; statusText?: string }
) => ({
  ok: init?.ok ?? true,
  status: init?.status ?? 200,
  statusText: init?.statusText ?? "OK",
  json: async () => data,
});

const failure = (status: number, data: unknown = { message: "Not found" }) =>
  jsonResponse(data, { ok: false, status, statusText: "Failed" });

const connectorError = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    if (error instanceof ConnectorError) return error.data;
    throw error;
  }
  throw new Error("expected the call to throw");
};

beforeEach(() => {
  mockedFetch.mockReset();
  logged.warn.mockClear();
  logged.error.mockClear();
});

describe("login", () => {
  it("POSTs the key as a form and returns the session", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({
        access_token: "admin-token",
        token_type: "Bearer",
        expires_in: 3600,
      })
    );

    await expect(login(BASE_URL, adminKey)).resolves.toEqual(session);

    const [url, init] = mockedFetch.mock.calls[0];
    // The key is in the body, and not in the URL.
    expect(url).toBe("https://example.looker.app/api/4.0/login");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    });
    expect(init.body).toBe("client_id=admin-id&client_secret=admin-secret");
  });

  it.each([401, 403, 404])(
    "reports a %i as a key that Looker does not accept",
    async (status) => {
      mockedFetch.mockResolvedValue(failure(status));

      const data = await connectorError(() => login(BASE_URL, adminKey));

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({ status, reason: "admin_key_rejected" });
      expect(data.message).toBe(
        "Looker did not accept the Admin API key at https://example.looker.app. Check the instance URL, and the key in the Admin key secret."
      );
    }
  );

  it("does not report a quota refusal as a key that Looker does not accept", async () => {
    mockedFetch.mockResolvedValue(
      failure(403, { message: "API quota exceeded" })
    );

    const data = await connectorError(() => login(BASE_URL, adminKey));

    expect(data.type).toBe("rate_limited");
  });

  it("fails when Looker returns no access token", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({}));

    const data = await connectorError(() => login(BASE_URL, adminKey));

    expect(data.type).toBe("unknown");
    expect(data.message).toBe(
      "Looker returned no access token for the Admin API key"
    );
  });
});

describe("logout", () => {
  it("DELETEs the session's token", async () => {
    mockedFetch.mockResolvedValue(jsonResponse(undefined, { status: 204 }));

    await expect(logout(session)).resolves.toBeUndefined();

    expect(mockedFetch).toHaveBeenCalledWith(
      "https://example.looker.app/api/4.0/logout",
      expect.objectContaining({ method: "DELETE" })
    );
  });
});

describe("createServiceAccount", () => {
  it("POSTs the name and returns the account's id", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ id: "42" }));

    await expect(createServiceAccount(session, "p0_grant")).resolves.toBe("42");

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe(
      "https://example.looker.app/api/4.0/users/service_accounts?fields=id"
    );
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({
      Accept: "application/json",
      Authorization: "token admin-token",
      "Content-Type": "application/json",
    });
    // No roles: the API marks them read-only on this call (W2).
    expect(JSON.parse(init.body)).toEqual({ service_account_name: "p0_grant" });
  });

  it("returns a numeric id as a string", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ id: 42 }));

    await expect(createServiceAccount(session, "p0_grant")).resolves.toBe("42");
  });

  it("fails when Looker returns no id", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({}));

    const data = await connectorError(() =>
      createServiceAccount(session, "p0_grant")
    );

    expect(data.type).toBe("unknown");
  });
});

describe("setUserName", () => {
  it("PATCHes the user's first and last name", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ id: "42" }));

    await setUserName(session, "42", { firstName: "P0", lastName: "p0_grant" });

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe("https://example.looker.app/api/4.0/users/42?fields=id");
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body)).toEqual({
      first_name: "P0",
      last_name: "p0_grant",
    });
  });
});

describe("createApiKey", () => {
  it("POSTs to the user's API keys and returns the client ID and secret", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({
        id: "7",
        client_id: "grant-id",
        client_secret: "grant-secret",
        created_at: "2026-10-11T00:00:00Z",
      })
    );

    await expect(createApiKey(session, "42")).resolves.toEqual({
      client_id: "grant-id",
      client_secret: "grant-secret",
    });

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe(
      "https://example.looker.app/api/4.0/users/42/credentials_api3"
    );
    expect(init.method).toBe("POST");
    expect(init.body).toBeUndefined();
    expect(init.headers).toEqual({
      Accept: "application/json",
      Authorization: "token admin-token",
    });
  });

  it("fails when Looker returns no client secret", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ client_id: "grant-id" }));

    const data = await connectorError(() => createApiKey(session, "42"));

    expect(data.type).toBe("unknown");
    expect(data.message).toBe(
      "Looker returned an API key without its client ID or client secret"
    );
  });
});

describe("listServiceAccounts", () => {
  it("returns each exact match with its first name", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse([
        { id: "1", service_account_name: "p0_grant", first_name: "P0" },
        { id: "2", service_account_name: "p0_grant", first_name: null },
        { id: "3", service_account_name: "p0_grant-other", first_name: "P0" },
      ])
    );

    await expect(listServiceAccounts(session, "p0_grant")).resolves.toEqual([
      { id: "1", firstName: "P0" },
      { id: "2", firstName: undefined },
    ]);
  });
});

describe("listServiceAccountIds", () => {
  const find = () => listServiceAccountIds(session, "p0_grant");
  const accounts = (...names: (string | null)[]) =>
    jsonResponse(
      names.map((name, i) => ({ id: String(i), service_account_name: name }))
    );

  it("reads the Looker service accounts and returns the exact match", async () => {
    mockedFetch.mockResolvedValue(
      accounts("p0_grant-other", "p0_grant", "P0_GRANT", null)
    );

    await expect(find()).resolves.toEqual(["1"]);

    const [url, init] = mockedFetch.mock.calls[0];
    expect(init.method).toBe("GET");
    expect(url).toContain("https://example.looker.app/api/4.0/users/search?");
    expect(Object.fromEntries(new URL(url).searchParams)).toEqual({
      is_service_account: "true",
      fields: "id,service_account_name,first_name",
      sorts: "id",
      limit: "100",
      offset: "0",
    });
  });

  it("fails when Looker returns something other than a list", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ id: "1" }));

    const data = await connectorError(find);

    expect(data.type).toBe("unknown");
    expect(data.message).toMatch(
      /^Looker GET \/users\/search\?.* returned a response the connector doesn't recognize$/
    );
  });

  it("returns nothing when no account has the name", async () => {
    mockedFetch.mockResolvedValue(accounts("p0_grant-other"));

    await expect(find()).resolves.toEqual([]);
  });

  it("returns every account with the name", async () => {
    mockedFetch.mockResolvedValue(accounts("p0_grant", "other", "p0_grant"));

    await expect(find()).resolves.toEqual(["0", "2"]);
  });

  const page = (ids: number[], target?: number) =>
    jsonResponse(
      ids.map((id) => ({
        id: String(id),
        service_account_name: id === target ? "p0_grant" : "other",
      }))
    );
  const range = (from: number, to: number) =>
    Array.from({ length: to - from + 1 }, (_, i) => from + i);

  it("reads every page, each starting 10 rows before the last one ends", async () => {
    mockedFetch
      .mockResolvedValueOnce(page(range(1, 100)))
      .mockResolvedValueOnce(page(range(91, 101), 101));

    await expect(find()).resolves.toEqual(["101"]);

    expect(mockedFetch).toHaveBeenCalledTimes(2);
    const [url] = mockedFetch.mock.calls[1];
    expect(new URL(url).searchParams.get("offset")).toBe("90");
  });

  it("returns a row that two pages share once", async () => {
    mockedFetch
      .mockResolvedValueOnce(page(range(1, 100), 95))
      .mockResolvedValueOnce(page(range(91, 101)));

    await expect(find()).resolves.toEqual(["95"]);
  });

  // Another revoke can delete a row between two page reads, which moves every
  // later row up a place.
  it("finds the account when a row before it is deleted between two pages", async () => {
    const before = range(1, 120);
    const after = before.filter((id) => id !== 5);
    mockedFetch.mockImplementation(async (url: string) => {
      const query = new URL(url).searchParams;
      const offset = Number(query.get("offset"));
      const rows = mockedFetch.mock.calls.length === 1 ? before : after;
      return page(rows.slice(offset, offset + Number(query.get("limit"))), 101);
    });

    await expect(find()).resolves.toEqual(["101"]);
  });

  it("stops after 50 pages", async () => {
    mockedFetch.mockResolvedValue(
      accounts(...Array<string>(100).fill("other"))
    );

    const data = await connectorError(find);

    expect(data.type).toBe("unknown");
    expect(data.message).toBe(
      "The Looker instance has at least 4510 Looker service accounts, which is more than the connector searches"
    );
    expect(mockedFetch).toHaveBeenCalledTimes(50);
  });
});

describe("deleteServiceAccount", () => {
  const remove = () => deleteServiceAccount(session, "42");

  it("accepts a 204 response", async () => {
    mockedFetch.mockResolvedValue(jsonResponse(undefined, { status: 204 }));

    await expect(remove()).resolves.toBeUndefined();

    expect(mockedFetch).toHaveBeenCalledWith(
      "https://example.looker.app/api/4.0/users/service_accounts/42",
      expect.objectContaining({ method: "DELETE" })
    );
  });

  it("treats an account that is already gone as deleted", async () => {
    mockedFetch.mockResolvedValue(failure(404));

    await expect(remove()).resolves.toBeUndefined();
  });

  it("propagates any other failure", async () => {
    mockedFetch.mockResolvedValue(failure(403, { message: "Forbidden" }));

    const data = await connectorError(remove);

    expect(data.type).toBe("insufficient_privileges");
    expect(data.message).toBe(
      "Looker DELETE /users/service_accounts/42 failed (403): Forbidden"
    );
    expect(data.payload).toEqual({ status: 403 });
  });
});

const requestOf = (index = 0) => {
  const [url, init] = mockedFetch.mock.calls[index];
  const parsed = new URL(url);
  return {
    method: init.method as string,
    path: parsed.pathname.replace("/api/4.0", ""),
    query: Object.fromEntries(parsed.searchParams),
    body: init.body === undefined ? undefined : JSON.parse(init.body),
  };
};

describe("listPermissionParents", () => {
  it("GETs every permission with its parent", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse([
        { permission: "access_data", parent: null, description: "..." },
        { permission: "see_looks", parent: "access_data" },
        { permission: "see_lookml" },
        { permission: "odd", parent: "" },
        { permission: null, parent: "access_data" },
      ])
    );

    const parents = await listPermissionParents(session);

    expect([...parents]).toEqual([
      ["access_data", null],
      ["see_looks", "access_data"],
      ["see_lookml", null],
      ["odd", null],
    ]);
    expect(requestOf()).toEqual({
      method: "GET",
      path: "/permissions",
      query: {},
      body: undefined,
    });
  });
});

// The three kinds are found and created alike.
describe.each([
  {
    kind: "permission set",
    find: (name: string) => findPermissionSet(session, name),
    create: () =>
      createPermissionSet(session, {
        name: "p0-looker-ai-read",
        permissions: ["access_data", "see_looks"],
      }),
    searchPath: "/permission_sets/search",
    createPath: "/permission_sets",
    fields: "id,name,permissions",
    row: (id: number | string, name: string | null) => ({
      id,
      name,
      permissions: ["access_data", "see_looks"],
      built_in: false,
    }),
    parsed: (id: string, name: string) => ({
      id,
      name,
      permissions: ["access_data", "see_looks"],
    }),
    createBody: {
      name: "p0-looker-ai-read",
      permissions: ["access_data", "see_looks"],
    },
  },
  {
    kind: "model set",
    find: (name: string) => findModelSet(session, name),
    create: () =>
      createModelSet(session, { name: "p0-looker-ai-read", models: ["a_b"] }),
    searchPath: "/model_sets/search",
    createPath: "/model_sets",
    fields: "id,name,models",
    row: (id: number | string, name: string | null) => ({
      id,
      name,
      models: ["a_b"],
    }),
    parsed: (id: string, name: string) => ({ id, name, models: ["a_b"] }),
    createBody: { name: "p0-looker-ai-read", models: ["a_b"] },
  },
  {
    kind: "role",
    find: (name: string) => findRole(session, name),
    create: () =>
      createRole(session, {
        name: "p0-looker-ai-read",
        permissionSetId: "11",
        modelSetId: "12",
      }),
    searchPath: "/roles/search",
    createPath: "/roles",
    fields: "id,name,permission_set,model_set",
    row: (id: number | string, name: string | null) => ({
      id,
      name,
      permission_set: { id: 11, name: "x", permissions: ["access_data"] },
      model_set: { id: "12", name: "y", models: ["a_b"] },
    }),
    parsed: (id: string, name: string) => ({
      id,
      name,
      permissionSetId: "11",
      modelSetId: "12",
    }),
    createBody: {
      name: "p0-looker-ai-read",
      permission_set_id: "11",
      model_set_id: "12",
    },
  },
])("a $kind", (kind) => {
  const NAME = "p0-looker-ai-read";

  describe("found by name", () => {
    it("is searched for by name, and returned with its contents", async () => {
      mockedFetch.mockResolvedValue(jsonResponse([kind.row("7", NAME)]));

      await expect(kind.find(NAME)).resolves.toEqual(kind.parsed("7", NAME));

      expect(requestOf()).toEqual({
        method: "GET",
        path: kind.searchPath,
        query: {
          name: NAME,
          fields: kind.fields,
          sorts: "id",
          limit: "100",
          offset: "0",
        },
        body: undefined,
      });
    });

    it("is undefined when Looker finds nothing", async () => {
      mockedFetch.mockResolvedValue(jsonResponse([]));

      await expect(kind.find(NAME)).resolves.toBeUndefined();
    });

    // Looker's search ignores case, and reads `_` and `%` as wildcards.
    it.each([
      ["another case", "P0-Looker-AI-Read"],
      ["a longer name", "p0-looker-ai-read-only"],
      ["a wildcard's match", "p0-looker-ai_read"],
      ["no name", null],
    ])("is not one that Looker returns with %s", async (_, name) => {
      mockedFetch.mockResolvedValue(jsonResponse([kind.row("7", name)]));

      await expect(kind.find(NAME)).resolves.toBeUndefined();
    });

    it("is picked out of the near matches that Looker returns", async () => {
      mockedFetch.mockResolvedValue(
        jsonResponse([
          kind.row("5", "P0-LOOKER-AI-READ"),
          kind.row("7", NAME),
          kind.row("9", "p0-looker-ai-readx"),
        ])
      );

      await expect(kind.find(NAME)).resolves.toMatchObject({ id: "7" });
    });

    // Grants that race to create one must settle on the same one.
    it.each([
      ["in Looker's order", ["9", "10", "100"], "9"],
      ["in any order", ["100", "9", "10"], "9"],
      ["as numbers", [30, 4, 200], "4"],
    ])(
      "is the one with the lowest id when several share the name, %s",
      async (_, ids, lowest) => {
        mockedFetch.mockResolvedValue(
          jsonResponse(ids.map((id) => kind.row(id, NAME)))
        );

        await expect(kind.find(NAME)).resolves.toMatchObject({ id: lowest });
      }
    );

    it("is searched for on every page", async () => {
      mockedFetch
        .mockResolvedValueOnce(
          jsonResponse(
            Array.from({ length: 100 }, (_, i) => kind.row(i + 1, "other"))
          )
        )
        .mockResolvedValueOnce(jsonResponse([kind.row("101", NAME)]));

      await expect(kind.find(NAME)).resolves.toMatchObject({ id: "101" });

      expect(requestOf(1).query.offset).toBe("90");
    });

    it("fails on a response that isn't a list of them", async () => {
      mockedFetch.mockResolvedValue(jsonResponse([{ name: NAME }]));

      const data = await connectorError(() => kind.find(NAME));

      expect(data.type).toBe("unknown");
      expect(data.message).toContain(
        "returned a response the connector doesn't recognize"
      );
    });
  });

  describe("created", () => {
    it("is POSTed, and returned as Looker made it", async () => {
      mockedFetch.mockResolvedValue(jsonResponse(kind.row(21, NAME)));

      await expect(kind.create()).resolves.toEqual(kind.parsed("21", NAME));

      expect(requestOf()).toEqual({
        method: "POST",
        path: kind.createPath,
        query: {},
        body: kind.createBody,
      });
    });

    // Looker's answer to a duplicate create is undocumented. The framework
    // maps both statuses to `unknown`, so the client tells them apart.
    it.each([
      ["a 409", 409, { message: "Conflict" }],
      [
        "a 422 whose error code is already_exists",
        422,
        {
          message: "Validation Failed",
          errors: [{ field: "name", code: "already_exists", message: "x" }],
        },
      ],
      [
        "a 422 that says the name has already been taken",
        422,
        {
          message: "Validation Failed",
          errors: [{ field: "name", message: "has already been taken" }],
        },
      ],
      [
        "a 422 that says it already exists",
        422,
        { message: "Name already exists" },
      ],
      [
        "a 422 that says it must be unique",
        422,
        { message: "name must be unique" },
      ],
    ])("reports %s as already_exists", async (_, status, body) => {
      mockedFetch.mockResolvedValue(failure(status, body));

      const data = await connectorError(kind.create);

      expect(data).toEqual({
        type: "already_exists",
        message: `Looker already has a ${kind.kind} named ${NAME}`,
        payload: { kind: kind.kind, name: NAME },
      });
    });

    it.each([
      [
        "a 422 for another reason",
        422,
        {
          message: "Validation Failed",
          errors: [{ field: "models", code: "invalid", message: "not found" }],
        },
        "unknown",
      ],
      [
        "a 400 that says it already exists",
        400,
        { message: "already exists" },
        "unknown",
      ],
      ["a 403", 403, { message: "Forbidden" }, "insufficient_privileges"],
      ["a 500", 500, { message: "already exists" }, "upstream_unavailable"],
    ])("reports %s as before", async (_, status, body, type) => {
      mockedFetch.mockResolvedValue(failure(status, body));

      const data = await connectorError(kind.create);

      expect(data.type).toBe(type);
      expect(data.payload).toEqual({ status });
    });
  });
});

describe("findRole", () => {
  it("returns a role without a permission set or a model set as having none", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse([{ id: "7", name: "r", permission_set: null }])
    );

    await expect(findRole(session, "r")).resolves.toEqual({
      id: "7",
      name: "r",
      permissionSetId: undefined,
      modelSetId: undefined,
    });
  });
});

describe("setUserRoles", () => {
  it("PUTs the role ids as the user's roles", async () => {
    mockedFetch.mockResolvedValue(jsonResponse([{ id: "3" }]));

    await expect(setUserRoles(session, "42", ["3"])).resolves.toBeUndefined();

    expect(requestOf()).toEqual({
      method: "PUT",
      path: "/users/42/roles",
      query: { fields: "id" },
      body: ["3"],
    });
  });

  it("PUTs an empty list to clear them", async () => {
    mockedFetch.mockResolvedValue(jsonResponse([]));

    await setUserRoles(session, "42", []);

    expect(requestOf().body).toEqual([]);
  });
});

describe("listDirectRoleIds", () => {
  it("GETs the roles given to the user directly, and not those of its groups", async () => {
    mockedFetch.mockResolvedValue(jsonResponse([{ id: "3" }, { id: 4 }]));

    await expect(listDirectRoleIds(session, "42")).resolves.toEqual(["3", "4"]);

    expect(requestOf()).toEqual({
      method: "GET",
      path: "/users/42/roles",
      query: { direct_association_only: "true", fields: "id" },
      body: undefined,
    });
  });
});

describe("listModels", () => {
  it("GETs the models that have an Explore and aren't hidden, with their labels", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse([
        { name: "thelook", label: "The Look" },
        { name: "finance_2", label: null },
        { name: "ops", label: "" },
        { name: null, label: "Nameless" },
      ])
    );

    await expect(listModels(session)).resolves.toEqual([
      { name: "thelook", label: "The Look" },
      { name: "finance_2", label: "finance_2" },
      { name: "ops", label: "ops" },
    ]);

    expect(requestOf()).toEqual({
      method: "GET",
      path: "/lookml_models",
      query: {
        fields: "name,label",
        exclude_empty: "true",
        exclude_hidden: "true",
      },
      body: undefined,
    });
  });
});

describe("findFolder", () => {
  it("GETs the folder and returns the id of its content metadata", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({ id: "77", content_metadata_id: 770 })
    );

    await expect(findFolder(session, "77")).resolves.toEqual({
      contentMetadataId: "770",
    });

    expect(requestOf()).toEqual({
      method: "GET",
      path: "/folders/77",
      query: { fields: "id,content_metadata_id" },
      body: undefined,
    });
  });

  it("is undefined when Looker has no such folder", async () => {
    mockedFetch.mockResolvedValue(failure(404));

    await expect(findFolder(session, "77")).resolves.toBeUndefined();
  });

  it("propagates any other failure", async () => {
    mockedFetch.mockResolvedValue(failure(403, { message: "Forbidden" }));

    const data = await connectorError(() => findFolder(session, "77"));

    expect(data.type).toBe("insufficient_privileges");
  });

  it("fails on a folder without content metadata", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ id: "77" }));

    const data = await connectorError(() => findFolder(session, "77"));

    expect(data.type).toBe("unknown");
  });
});

describe("listContentAccess", () => {
  it("GETs the access records of the content metadata", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse([
        { id: "1", user_id: "42", permission_type: "edit" },
        { id: 2, user_id: null, group_id: "1", permission_type: "view" },
        { id: "3", user_id: 43 },
      ])
    );

    await expect(listContentAccess(session, "770")).resolves.toEqual([
      { id: "1", userId: "42", permissionType: "edit" },
      { id: "2", userId: undefined, permissionType: "view" },
      { id: "3", userId: "43", permissionType: "" },
    ]);

    expect(requestOf()).toEqual({
      method: "GET",
      path: "/content_metadata_access",
      query: {
        content_metadata_id: "770",
        fields: "id,user_id,permission_type",
      },
      body: undefined,
    });
  });
});

describe("createContentAccess", () => {
  it("POSTs the user's access to the content metadata", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ id: "9" }));

    await createContentAccess(session, {
      contentMetadataId: "770",
      userId: "42",
      permissionType: "edit",
    });

    expect(requestOf()).toEqual({
      method: "POST",
      path: "/content_metadata_access",
      query: {},
      body: {
        content_metadata_id: "770",
        user_id: "42",
        permission_type: "edit",
      },
    });
  });
});

describe("updateContentAccess", () => {
  it("PUTs the access record's new level", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ id: "9" }));

    await updateContentAccess(session, "9", "edit");

    expect(requestOf()).toEqual({
      method: "PUT",
      path: "/content_metadata_access/9",
      query: {},
      body: { permission_type: "edit" },
    });
  });
});

describe("deleteContentAccess", () => {
  const remove = () => deleteContentAccess(session, "9");

  it("DELETEs the access record", async () => {
    mockedFetch.mockResolvedValue(jsonResponse(undefined, { status: 204 }));

    await expect(remove()).resolves.toBeUndefined();

    expect(requestOf()).toEqual({
      method: "DELETE",
      path: "/content_metadata_access/9",
      query: {},
      body: undefined,
    });
  });

  it("treats a record that is already gone as deleted", async () => {
    mockedFetch.mockResolvedValue(failure(404));

    await expect(remove()).resolves.toBeUndefined();
  });

  it("propagates any other failure", async () => {
    mockedFetch.mockResolvedValue(failure(403, { message: "Forbidden" }));

    const data = await connectorError(remove);

    expect(data.type).toBe("insufficient_privileges");
  });
});

describe("listGroupsWithRoles", () => {
  it("GETs every group with the names of its roles", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse([
        {
          id: 1,
          name: "All Users",
          include_by_default: false,
          roles: [
            { id: "2", name: "Viewer" },
            { id: "3", name: null },
          ],
        },
        { id: "7", name: "BI", include_by_default: true, roles: null },
        { id: "8" },
      ])
    );

    await expect(listGroupsWithRoles(session)).resolves.toEqual([
      {
        id: "1",
        name: "All Users",
        includeByDefault: false,
        roles: ["Viewer"],
      },
      { id: "7", name: "BI", includeByDefault: true, roles: [] },
      { id: "8", name: "", includeByDefault: false, roles: [] },
    ]);

    expect(requestOf()).toEqual({
      method: "GET",
      path: "/groups/search/with_roles",
      query: {
        fields: "id,name,include_by_default,roles",
        sorts: "id",
        limit: "100",
        offset: "0",
      },
      body: undefined,
    });
  });

  it("reads every page", async () => {
    mockedFetch
      .mockResolvedValueOnce(
        jsonResponse(Array.from({ length: 100 }, (_, i) => ({ id: i + 1 })))
      )
      .mockResolvedValueOnce(jsonResponse([{ id: 101 }]));

    await expect(listGroupsWithRoles(session)).resolves.toHaveLength(101);
  });

  it("stops after 50 pages", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse(Array.from({ length: 100 }, (_, i) => ({ id: i + 1 })))
    );

    const data = await connectorError(() => listGroupsWithRoles(session));

    expect(data.message).toBe(
      "The Looker instance has at least 4510 groups, which is more than the connector searches"
    );
    expect(mockedFetch).toHaveBeenCalledTimes(50);
  });
});

describe("request failures", () => {
  const call = () => createServiceAccount(session, "p0_grant");

  it.each([
    [400, "unknown"],
    [401, "insufficient_privileges"],
    [403, "insufficient_privileges"],
    [404, "object_not_found"],
    [409, "unknown"],
    [422, "unknown"],
    [500, "upstream_unavailable"],
    [503, "upstream_unavailable"],
  ])("reports a %i as %s", async (status, type) => {
    mockedFetch.mockResolvedValue(failure(status));

    const data = await connectorError(call);

    expect(data.type).toBe(type);
    expect(data.payload).toEqual({ status });
  });

  it("reports a 429 as the API limit, and does not retry", async () => {
    mockedFetch.mockResolvedValue(
      failure(429, { message: "Too many requests" })
    );

    const data = await connectorError(call);

    expect(data.type).toBe("rate_limited");
    expect(data.message).toBe(
      "Looker API limit reached. Looker POST /users/service_accounts?fields=id failed (429): Too many requests"
    );
    expect(mockedFetch).toHaveBeenCalledTimes(1);
  });

  // Looker does not document what it answers when the monthly quota runs out.
  it.each([
    "API quota exceeded for this instance",
    "Rate limit reached",
    "Admin API call limit exceeded",
  ])("reports a 403 that says %j as the API limit", async (message) => {
    mockedFetch.mockResolvedValue(failure(403, { message }));

    const data = await connectorError(call);

    expect(data.type).toBe("rate_limited");
    expect(data.message).toContain("Looker API limit reached. ");
    expect(mockedFetch).toHaveBeenCalledTimes(1);
  });

  it("reports the field and message of Looker's validation errors", async () => {
    mockedFetch.mockResolvedValue(
      failure(422, {
        message: "Validation Failed",
        errors: [
          {
            field: "service_account_name",
            code: "invalid",
            message: "is too long",
          },
        ],
      })
    );

    const data = await connectorError(call);

    expect(data.message).toBe(
      "Looker POST /users/service_accounts?fields=id failed (422): Validation Failed; service_account_name is too long"
    );
  });

  it("falls back to the status text when the error is not JSON", async () => {
    mockedFetch.mockResolvedValue({
      ok: false,
      status: 502,
      statusText: "Bad Gateway",
      json: async () => {
        throw new SyntaxError("Unexpected token <");
      },
    });

    const data = await connectorError(call);

    expect(data.message).toBe(
      "Looker POST /users/service_accounts?fields=id failed (502): Bad Gateway"
    );
  });

  it("fails on a successful response that is not JSON", async () => {
    mockedFetch.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => {
        throw new SyntaxError("Unexpected token <");
      },
    });

    const data = await connectorError(call);

    expect(data.type).toBe("unknown");
    expect(data.message).toBe(
      "Looker POST /users/service_accounts?fields=id returned a response that is not JSON (200)"
    );
  });

  it.each([
    ["null", null],
    ["a list", [{ id: "42" }]],
    ["an id that is an object", { id: { value: "42" } }],
    ["an empty id", { id: "" }],
  ])(
    "fails on a successful response that is %s, quoting none of it",
    async (_, body) => {
      mockedFetch.mockResolvedValue(jsonResponse(body));

      const data = await connectorError(call);

      expect(data).toEqual({
        type: "unknown",
        message:
          "Looker POST /users/service_accounts?fields=id returned a response the connector doesn't recognize",
        payload: {},
      });
    }
  );

  it("does not quote an API key whose shape is wrong", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({ client_id: 7, client_secret: "grant-secret" })
    );

    const data = await connectorError(() => createApiKey(session, "42"));

    expect(data.message).toBe(
      "Looker POST /users/42/credentials_api3 returned a response the connector doesn't recognize"
    );
    expect(JSON.stringify(data)).not.toContain("grant-secret");
  });

  it("leaves out the parts of an error body it doesn't recognize", async () => {
    mockedFetch.mockResolvedValue(
      failure(422, {
        message: "Validation Failed",
        errors: [null, { field: 7, message: "is taken" }, "x"],
      })
    );

    const data = await connectorError(call);

    expect(data.message).toBe(
      "Looker POST /users/service_accounts?fields=id failed (422): Validation Failed; is taken"
    );
  });

  it("does not follow a redirect to another host", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ id: "42" }));

    await call();

    const [, init] = mockedFetch.mock.calls[0];
    expect(init.redirect).toBe("error");
  });

  it("does not put the key or the token in the error", async () => {
    mockedFetch.mockRejectedValue(new Error("socket hang up"));

    const fromLogin = await connectorError(() => login(BASE_URL, adminKey));
    const fromCall = await connectorError(call);

    expect(fromLogin.type).toBe("upstream_unavailable");
    expect(fromLogin.message).toBe("Looker POST /login failed: socket hang up");
    expect(JSON.stringify([fromLogin, fromCall])).not.toMatch(
      /admin-secret|admin-token/
    );
  });
});

// A failed Looker call is a vendor error, not a bug in the connector, and some
// are expected, like the 404 of a folder that isn't there.
describe("log levels", () => {
  it.each<[string, () => void, () => Promise<unknown>, string]>([
    [
      "a network failure",
      () => mockedFetch.mockRejectedValue(new Error("socket hang up")),
      () => listModels(session),
      "Looker request failed",
    ],
    [
      "an error status",
      () => mockedFetch.mockResolvedValue(failure(500)),
      () => listModels(session),
      "Looker request returned a non-2xx response",
    ],
    [
      "a 404 that the call expects",
      () => mockedFetch.mockResolvedValue(failure(404)),
      () => findFolder(session, "77"),
      "Looker request returned a non-2xx response",
    ],
    [
      "a body of another shape",
      () => mockedFetch.mockResolvedValue(jsonResponse({ models: [] })),
      () => listModels(session),
      "Looker returned an unexpected response",
    ],
  ])("warns about %s", async (_, respond, call, message) => {
    respond();

    await call().catch(() => undefined);

    expect(logged.warn).toHaveBeenCalledWith(expect.anything(), message);
    expect(logged.error).not.toHaveBeenCalled();
  });
});

describe("a quota named in an error", () => {
  const call = () => createServiceAccount(session, "p0_grant");

  // Only a 403 can be the quota. Any other status keeps its own meaning.
  it.each([
    [404, "object_not_found"],
    [500, "upstream_unavailable"],
  ])("leaves a %i as %s", async (status, type) => {
    mockedFetch.mockResolvedValue(
      failure(status, { message: "API quota exceeded" })
    );

    const data = await connectorError(call);

    expect(data.type).toBe(type);
    expect(data.message).toBe(
      `Looker POST /users/service_accounts?fields=id failed (${status}): API quota exceeded`
    );
  });
});

describe("a response without a body", () => {
  // A real 204 has no body to read as JSON.
  it("is accepted on a 204", async () => {
    mockedFetch.mockResolvedValue({
      ok: true,
      status: 204,
      statusText: "No Content",
      json: async () => {
        throw new SyntaxError("Unexpected end of JSON input");
      },
    });

    await expect(logout(session)).resolves.toBeUndefined();
  });

  it("fails on any other status, with the status in the payload", async () => {
    mockedFetch.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => {
        throw new SyntaxError("Unexpected end of JSON input");
      },
    });

    const data = await connectorError(() =>
      createServiceAccount(session, "p0_grant")
    );

    expect(data.payload).toEqual({ status: 200 });
  });
});

describe("a create refused with an error that is not JSON", () => {
  it.each([409, 422])("is a %i like any other", async (status) => {
    mockedFetch.mockResolvedValue({
      ok: false,
      status,
      statusText: "Failed",
      json: async () => {
        throw new SyntaxError("Unexpected token <");
      },
    });

    const data = await connectorError(() =>
      createModelSet(session, { name: "p0-looker-ai-read", models: ["a_b"] })
    );

    expect(data.type).toBe(status === 409 ? "already_exists" : "unknown");
  });
});

describe("an account Looker creates without an id", () => {
  it("fails with what Looker left out", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({}));

    const data = await connectorError(() =>
      createServiceAccount(session, "p0_grant")
    );

    expect(data).toEqual({
      type: "unknown",
      message: "Looker returned a Looker service account without an id",
      payload: {},
    });
  });
});

describe("a search that never ends", () => {
  const fullPage = (row: (i: number) => unknown) =>
    jsonResponse(Array.from({ length: 100 }, (_, i) => row(i + 1)));

  it("fails with the number of rows it read in the payload", async () => {
    mockedFetch.mockResolvedValue(fullPage((id) => ({ id })));

    const data = await connectorError(() => listGroupsWithRoles(session));

    expect(data.payload).toEqual({ limit: 4510 });
  });

  it("says which name it searched for", async () => {
    mockedFetch.mockResolvedValue(
      fullPage((id) => ({ id, name: "other", permissions: [] }))
    );

    const data = await connectorError(() =>
      findPermissionSet(session, "p0-looker-ai-read")
    );

    expect(data.message).toBe(
      "The Looker instance has at least 4510 matches for the name p0-looker-ai-read, which is more than the connector searches"
    );
  });
});

describe("of several objects that share a name", () => {
  const NAME = "p0-looker-ai-read";
  const find = (ids: (number | string)[]) => {
    mockedFetch.mockResolvedValue(
      jsonResponse(ids.map((id) => ({ id, name: NAME, permissions: [] })))
    );
    return findPermissionSet(session, NAME);
  };

  // Looker API 4.0 sends ids as strings, and nothing says they are numbers.
  it.each([
    ["a number before any other id", ["abc", "12", "b", "7"], "7"],
    ["a number, whichever comes first", ["7", "abc"], "7"],
    ["a number before an id that sorts first as text", ["-1", "7"], "7"],
    ["the first id by text, when none is a number", ["b", "c", "a"], "a"],
    ["the first id by text, in Looker's order", ["a", "b"], "a"],
  ])("picks %s", async (_, ids, first) => {
    await expect(find(ids)).resolves.toMatchObject({ id: first });
  });
});

describe("an object Looker returns without its contents", () => {
  it.each([
    [
      "permission set",
      () =>
        createPermissionSet(session, {
          name: "p0-looker-ai-read",
          permissions: ["access_data"],
        }),
      { id: "21", name: "", permissions: [] },
    ],
    [
      "model set",
      () =>
        createModelSet(session, { name: "p0-looker-ai-read", models: ["a_b"] }),
      { id: "21", name: "", models: [] },
    ],
    [
      "role",
      () =>
        createRole(session, {
          name: "p0-looker-ai-read",
          permissionSetId: "11",
          modelSetId: "12",
        }),
      {
        id: "21",
        name: "",
        permissionSetId: undefined,
        modelSetId: undefined,
      },
    ],
  ])("is a %s with none", async (_, create, expected) => {
    mockedFetch.mockResolvedValue(jsonResponse({ id: 21 }));

    await expect(create()).resolves.toStrictEqual(expected);
  });
});
