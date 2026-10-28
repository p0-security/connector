import { createLogger } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeAuth0,
  type FakeUser,
  failing,
  isCall,
  newFakeAuth0,
} from "../../../__tests__/fake-auth0.ts";
import {
  ALLOWED_PATTERN,
  CLIENT_ID,
  CLIENT_SECRET,
  CREDENTIALS,
  EMAIL,
  TENANT,
} from "../../../__tests__/fixtures.ts";
import { connectorError } from "../../../__tests__/helpers.ts";
import type { ListerQuery } from "../definition.ts";
import { list } from "../list.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const getClientSecret = vi.hoisted(() => vi.fn());
vi.mock("../../../secrets.ts", () => ({ getClientSecret }));

// Read when the first email is checked, as a deployment's is.
vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

const OUTSIDER = "mallory@evil.com";

const logger = createLogger();
logger.level = "silent";

let auth0: FakeAuth0;
let versions = 0;

const ALICE: FakeUser = {
  user_id: "auth0|alice",
  email: EMAIL,
  connection: "Username-Password-Authentication",
  roles: [],
  permissions: [],
};

const run = (query: ListerQuery) => list(logger, query);

const ids = (n: number, prefix: string) =>
  Array.from(
    { length: n },
    (_, i) => `${prefix}_${String(i).padStart(4, "0")}`
  );

beforeEach(() => {
  auth0 = newFakeAuth0({
    tenant: TENANT,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });
  vi.stubGlobal("fetch", auth0.fetch);
  getClientSecret.mockReset();
  getClientSecret.mockResolvedValue({
    secret: CLIENT_SECRET,
    version: `version-${++versions}`,
  });
  auth0.users.push({ ...ALICE, roles: [], permissions: [] });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("pagination", () => {
  it("returns [] for an empty listing, after one page", async () => {
    await expect(run({ type: "roles", context: CREDENTIALS })).resolves.toEqual(
      []
    );
    expect(auth0.apiCalls()).toHaveLength(1);
    expect(auth0.apiCalls()[0]?.query).toEqual({ page: "0", per_page: "100" });
  });

  it("asks for 100 a page, and stops at the first page that isn't full", async () => {
    auth0.roles.push(
      ...ids(150, "rol").map((id) => ({ id, name: id, permissions: [] }))
    );

    const roles = await run({ type: "roles", context: CREDENTIALS });

    expect(roles).toHaveLength(150);
    expect(auth0.apiCalls().map(({ query }) => query.page)).toEqual(["0", "1"]);
  });

  it("reads one more, empty, page when the last one is exactly full", async () => {
    auth0.roles.push(
      ...ids(200, "rol").map((id) => ({ id, name: id, permissions: [] }))
    );

    const roles = await run({ type: "roles", context: CREDENTIALS });

    expect(roles).toHaveLength(200);
    expect(new Set(roles.map(({ key }) => key)).size).toBe(200);
    expect(auth0.apiCalls().map(({ query }) => query.page)).toEqual([
      "0",
      "1",
      "2",
    ]);
  });

  // `page`/`per_page` stops at 1000 organizations. Checkpoints don't.
  it("lists more than 1000 organizations with from/take", async () => {
    auth0.organizations.push(
      ...ids(1050, "org").map((id) => ({
        id,
        name: id,
        members: new Map<string, string[]>(),
      }))
    );

    const organizations = await run({
      type: "organizations",
      context: CREDENTIALS,
    });

    expect(organizations).toHaveLength(1050);
    expect(organizations.at(-1)).toEqual({
      key: "org_1049",
      value: "org_1049",
    });
    const queries = auth0.apiCalls().map(({ query }) => query);
    expect(queries).toHaveLength(11);
    expect(queries[0]).toEqual({ take: "100" });
    expect(queries[1]).toEqual({ take: "100", from: "100" });
    expect(queries.every(({ page }) => page === undefined)).toBe(true);
  });

  it("stops listing organizations at a page without a next checkpoint", async () => {
    auth0.organizations.push({
      id: "org_1",
      name: "acme",
      members: new Map(),
    });

    await expect(
      run({ type: "organizations", context: CREDENTIALS })
    ).resolves.toEqual([{ key: "org_1", value: "acme" }]);
    expect(auth0.apiCalls()).toHaveLength(1);
  });
});

describe("users", () => {
  const users = (email = EMAIL) =>
    run({ type: "users", context: CREDENTIALS, email });

  it("finds the user with the email, with its connection", async () => {
    await expect(users()).resolves.toEqual([
      {
        key: "auth0|alice",
        value: "Username-Password-Authentication",
        group: EMAIL,
      },
    ]);
  });

  it("returns one entry per user when several connections have the email", async () => {
    auth0.users.push({
      ...ALICE,
      user_id: "google-oauth2|123",
      connection: "google-oauth2",
    });

    await expect(users()).resolves.toEqual([
      {
        key: "auth0|alice",
        value: "Username-Password-Authentication",
        group: EMAIL,
      },
      { key: "google-oauth2|123", value: "google-oauth2", group: EMAIL },
    ]);
  });

  // `/users-by-email` is case-sensitive, and only Auth0's own database users
  // are stored lower-cased.
  it("looks the email up as given and lower-cased, and merges the two", async () => {
    auth0.users.push({
      ...ALICE,
      user_id: "samlp|Alice",
      email: "Alice@acme.com",
      connection: "okta",
    });

    await expect(users("Alice@acme.com")).resolves.toEqual([
      { key: "samlp|Alice", value: "okta", group: "Alice@acme.com" },
      {
        key: "auth0|alice",
        value: "Username-Password-Authentication",
        group: EMAIL,
      },
    ]);
    expect(auth0.apiCalls().map(({ query }) => query.email)).toEqual([
      "Alice@acme.com",
      EMAIL,
    ]);
  });

  it("asks once when the email is already lower-case", async () => {
    await users();

    expect(auth0.apiCalls()).toHaveLength(1);
  });

  it("doesn't repeat a user both lookups find", async () => {
    auth0.intercept((call) =>
      isCall("GET", "/api/v2/users-by-email")(call)
        ? {
            status: 200,
            body: [
              {
                user_id: "auth0|alice",
                email: EMAIL,
                identities: [{ connection: "db" }],
              },
            ],
          }
        : undefined
    );

    await expect(users("ALICE@acme.com")).resolves.toEqual([
      { key: "auth0|alice", value: "db", group: EMAIL },
    ]);
  });

  it("returns [] when no user has the email", async () => {
    await expect(users("bob@acme.com")).resolves.toEqual([]);
  });

  it("refuses an email outside the allowed domains, and asks Auth0 nothing", async () => {
    const data = await connectorError(() => users(OUTSIDER));

    expect(data).toEqual({
      type: "validation_error",
      message: `Your email domain isn't allowed for Auth0 tenant ${TENANT}. Ask your P0 admin to check the connector's allowed domains.`,
      payload: {
        reason: "domain_not_allowed",
        tenant: TENANT,
        email: OUTSIDER,
      },
    });
    expect(auth0.calls).toEqual([]);
  });

  it("encodes the email as a query value", async () => {
    await users("a+b@acme.com");

    expect(auth0.apiCalls()[0]?.url).toBe(
      `https://${TENANT}/api/v2/users-by-email?email=a%2Bb%40acme.com`
    );
  });
});

describe("the tenant-wide listings", () => {
  beforeEach(() => {
    auth0.roles.push({ id: "rol_admin", name: "Admin", permissions: [] });
    auth0.apis.push(
      {
        identifier: "https://api.acme.com",
        name: "Acme API",
        scopes: [
          { value: "read:things", description: "Read things" },
          { value: "write:things" },
        ],
      },
      { identifier: "urn:empty", name: "Empty", scopes: [] },
      {
        identifier: `https://${TENANT}/api/v2/`,
        name: "Auth0 Management API",
        is_system: true,
        scopes: [{ value: "read:users" }],
      }
    );
    auth0.organizations.push({ id: "org_1", name: "acme", members: new Map() });
  });

  it("lists the roles by id and name", async () => {
    await expect(run({ type: "roles", context: CREDENTIALS })).resolves.toEqual(
      [{ key: "rol_admin", value: "Admin" }]
    );
  });

  it("lists the APIs by identifier and name", async () => {
    await expect(run({ type: "apis", context: CREDENTIALS })).resolves.toEqual([
      { key: "https://api.acme.com", value: "Acme API" },
      { key: "urn:empty", value: "Empty" },
    ]);
  });

  it("lists an API's permissions, described when the API says", async () => {
    await expect(
      run({
        type: "permissions",
        context: CREDENTIALS,
        resourceServerIdentifier: "https://api.acme.com",
      })
    ).resolves.toEqual([
      { key: "read:things", value: "Read things" },
      { key: "write:things", value: "write:things" },
    ]);
  });

  // Auth0 refuses to assign a system API's permissions to a user.
  it("lists no permissions for the Management API", async () => {
    await expect(
      run({
        type: "permissions",
        context: CREDENTIALS,
        resourceServerIdentifier: `https://${TENANT}/api/v2/`,
      })
    ).resolves.toEqual([]);
  });

  it("lists no permissions for an API that isn't there", async () => {
    await expect(
      run({
        type: "permissions",
        context: CREDENTIALS,
        resourceServerIdentifier: "urn:gone",
      })
    ).resolves.toEqual([]);
  });

  it("lists the organizations by id and name", async () => {
    await expect(
      run({ type: "organizations", context: CREDENTIALS })
    ).resolves.toEqual([{ key: "org_1", value: "acme" }]);
  });

  // They aren't about anyone, and P0 lists them before it knows who's asking.
  it.each(["roles", "apis", "organizations"] as const)(
    "doesn't gate %s by the allowed domains",
    async (type) => {
      vi.stubEnv("DOMAIN_ALLOW_PATTERN", "^nothing$");

      await expect(run({ type, context: CREDENTIALS })).resolves.toBeDefined();
    }
  );

  it("maps an Auth0 failure onto a connector error", async () => {
    auth0.intercept((call) =>
      call.path === "/oauth/token"
        ? undefined
        : failing(403, "Insufficient scope")
    );

    const data = await connectorError(() =>
      run({ type: "roles", context: CREDENTIALS })
    );

    expect(data.type).toBe("insufficient_privileges");
  });
});

describe("the queries about a user", () => {
  const ADMIN = { id: "rol_admin", name: "Admin", permissions: [] };
  const READER = {
    id: "rol_reader",
    name: "Reader",
    permissions: [{ api: "https://api.acme.com", name: "read:things" }],
  };

  beforeEach(() => {
    auth0.roles.push(ADMIN, READER);
    const alice = auth0.users[0];
    if (!alice) throw new Error("no Alice");
    alice.roles.push("rol_admin");
  });

  const about = { context: CREDENTIALS, email: EMAIL, userId: "auth0|alice" };
  const userPermissions = {
    type: "user-permissions" as const,
    ...about,
    resourceServerIdentifier: "https://api.acme.com",
  };

  it("lists the roles assigned to the user directly", async () => {
    await expect(run({ type: "user-roles", ...about })).resolves.toEqual([
      { key: "rol_admin", value: "Admin" },
    ]);
  });

  it("lists only the permissions assigned to the user directly", async () => {
    const alice = auth0.users[0];
    alice?.roles.push("rol_reader");
    alice?.permissions.push(
      { api: "https://api.acme.com", name: "write:things" },
      // Also from the Reader role: still direct.
      { api: "https://api.acme.com", name: "read:things" },
      // Another API's.
      { api: "https://other.acme.com", name: "write:things" }
    );

    await expect(run(userPermissions)).resolves.toEqual([
      {
        key: "write:things",
        value: "write:things",
        group: "https://api.acme.com",
      },
      {
        key: "read:things",
        value: "read:things",
        group: "https://api.acme.com",
      },
    ]);
  });

  it("leaves out a permission only a role gives", async () => {
    auth0.users[0]?.roles.push("rol_reader");

    await expect(run(userPermissions)).resolves.toEqual([]);
  });

  it("asks Auth0 for the query's API only", async () => {
    await run(userPermissions);

    const call = auth0
      .apiCalls()
      .find(({ path }) => path.includes("/effective-permissions"));
    expect(call?.query).toMatchObject({
      resource_server_identifier: "https://api.acme.com",
    });
  });

  it("follows the checkpoint to the last page", async () => {
    const alice = auth0.users[0];
    for (let i = 0; i < 150; i++) {
      alice?.permissions.push({ api: "https://api.acme.com", name: `p:${i}` });
    }

    const permissions = await run(userPermissions);

    expect(permissions).toHaveLength(150);
    expect(permissions.at(-1)).toMatchObject({ key: "p:149" });
  });

  it.each(["direct", "DIRECT"])(
    "reads a direct source spelled %s",
    async (source) => {
      auth0.intercept((call) =>
        call.path.includes("/effective-permissions")
          ? {
              status: 200,
              body: {
                permissions: [
                  {
                    resource_server_identifier: "urn:api",
                    permission_name: "do:it",
                    sources: [source],
                  },
                  {
                    resource_server_identifier: "urn:api",
                    permission_name: "via:role",
                    sources: ["roles"],
                  },
                  {
                    resource_server_identifier: "urn:api",
                    permission_name: "no:sources",
                  },
                ],
              },
            }
          : undefined
      );

      await expect(
        run({ ...userPermissions, resourceServerIdentifier: "urn:api" })
      ).resolves.toEqual([{ key: "do:it", value: "do:it", group: "urn:api" }]);
    }
  );

  describe("org-membership", () => {
    const membership = {
      type: "org-membership" as const,
      ...about,
      organizationId: "org_1",
    };

    it("is [] when the user isn't a member", async () => {
      auth0.organizations.push({
        id: "org_1",
        name: "acme",
        members: new Map(),
      });

      await expect(run(membership)).resolves.toEqual([]);
      // The member's roles aren't read.
      expect(auth0.apiCalls().map(({ path }) => path)).not.toContainEqual(
        expect.stringContaining("/members/")
      );
    });

    it("says the user is a member, then lists its roles in the organization", async () => {
      auth0.organizations.push({
        id: "org_1",
        name: "acme",
        members: new Map([["auth0|alice", ["rol_reader"]]]),
      });

      await expect(run(membership)).resolves.toEqual([
        { key: "member", value: "auth0|alice" },
        { key: "rol_reader", value: "Reader", group: "role" },
      ]);
    });

    it("says a member without roles is a member", async () => {
      auth0.organizations.push({
        id: "org_1",
        name: "acme",
        members: new Map([["auth0|alice", []]]),
      });

      await expect(run(membership)).resolves.toEqual([
        { key: "member", value: "auth0|alice" },
      ]);
    });

    it("refuses an organization id that could change the URL", async () => {
      await expect(
        run({ ...membership, organizationId: "../users" })
      ).rejects.toThrow();
      expect(auth0.calls).toEqual([]);
    });
  });

  describe.each([
    ["user-roles"],
    ["user-permissions"],
    ["org-membership"],
  ] as const)("%s", (type) => {
    const query = (change: Partial<typeof about> = {}) =>
      ({
        type,
        ...about,
        ...change,
        organizationId: "org_1",
        resourceServerIdentifier: "https://api.acme.com",
      }) as ListerQuery;

    beforeEach(() => {
      auth0.organizations.push({
        id: "org_1",
        name: "acme",
        members: new Map(),
      });
    });

    it("refuses an email outside the allowed domains, and asks Auth0 nothing", async () => {
      const data = await connectorError(() => run(query({ email: OUTSIDER })));

      expect(data.payload).toMatchObject({ reason: "domain_not_allowed" });
      expect(auth0.calls).toEqual([]);
    });

    it("refuses a user id whose user has another email", async () => {
      auth0.users.push({
        ...ALICE,
        user_id: "auth0|bob",
        email: "bob@acme.com",
      });

      const data = await connectorError(() =>
        run(query({ userId: "auth0|bob" }))
      );

      expect(data).toEqual({
        type: "validation_error",
        message: `Your Auth0 user in ${TENANT} changed after you requested access. Request access again.`,
        payload: {
          reason: "user_changed",
          tenant: TENANT,
          email: EMAIL,
          userId: "auth0|bob",
        },
      });
      expect(auth0.apiCalls()).toHaveLength(1);
    });

    it("refuses a user id whose user has no email", async () => {
      auth0.intercept((call) =>
        isCall("GET", "/api/v2/users/auth0%7Calice")(call)
          ? { status: 200, body: { user_id: "auth0|alice" } }
          : undefined
      );

      const data = await connectorError(() => run(query()));

      expect(data.payload).toMatchObject({ reason: "user_changed" });
    });

    it("refuses a user id that names no user", async () => {
      const data = await connectorError(() =>
        run(query({ userId: "auth0|gone" }))
      );

      expect(data.payload).toMatchObject({ reason: "user_changed" });
    });

    it("matches the user's email ignoring case", async () => {
      await expect(
        run(query({ email: "ALICE@acme.com" }))
      ).resolves.toBeDefined();
    });

    it("encodes the user id as a path segment", async () => {
      auth0.users.push({ ...ALICE, user_id: "auth0|a/b", email: EMAIL });

      await run(query({ userId: "auth0|a/b" }));

      expect(auth0.apiCalls()[0]?.path).toBe("/api/v2/users/auth0%7Ca%2Fb");
    });
  });
});

describe("what the lookups answer at their edges", () => {
  it("leaves the connection and email empty for a user without them", async () => {
    auth0.intercept((call) =>
      isCall("GET", "/api/v2/users-by-email")(call)
        ? {
            status: 200,
            body: [
              { user_id: "auth0|a", identities: [] },
              { user_id: "auth0|b" },
            ],
          }
        : undefined
    );

    await expect(
      run({ type: "users", context: CREDENTIALS, email: EMAIL })
    ).resolves.toEqual([
      { key: "auth0|a", value: "", group: "" },
      { key: "auth0|b", value: "", group: "" },
    ]);
  });

  it("lists no permissions for an API that defines none", async () => {
    auth0.intercept((call) =>
      isCall("GET", "/api/v2/resource-servers")(call)
        ? { status: 200, body: [{ identifier: "urn:bare", name: "Bare" }] }
        : undefined
    );

    await expect(
      run({
        type: "permissions",
        context: CREDENTIALS,
        resourceServerIdentifier: "urn:bare",
      })
    ).resolves.toEqual([]);
  });

  it("stops listing organizations at an empty page, even with a next checkpoint", async () => {
    auth0.intercept((call) =>
      isCall("GET", "/api/v2/organizations")(call)
        ? { status: 200, body: { organizations: [], next: "more" } }
        : undefined
    );

    await expect(
      run({ type: "organizations", context: CREDENTIALS })
    ).resolves.toEqual([]);
    expect(auth0.apiCalls()).toHaveLength(1);
  });

  it("reads only the user fields it needs", async () => {
    await run({
      type: "user-roles",
      context: CREDENTIALS,
      email: EMAIL,
      userId: "auth0|alice",
    });

    expect(auth0.apiCalls()[0]?.query).toEqual({
      fields: "user_id,email,identities",
      include_fields: "true",
    });
  });

  it("says a member of another organization isn't a member of this one", async () => {
    auth0.organizations.push(
      { id: "org_1", name: "acme", members: new Map() },
      {
        id: "org_2",
        name: "other",
        members: new Map([["auth0|alice", []]]),
      }
    );

    await expect(
      run({
        type: "org-membership",
        context: CREDENTIALS,
        email: EMAIL,
        userId: "auth0|alice",
        organizationId: "org_1",
      })
    ).resolves.toEqual([]);
  });

  // An Auth0 user that can't be read is Auth0 failing, not the user changing.
  it("fails as upstream_unavailable when the user can't be read", async () => {
    auth0.intercept((call) =>
      isCall("GET", "/api/v2/users/auth0%7Calice")(call)
        ? failing(503)
        : undefined
    );

    const data = await connectorError(() =>
      run({
        type: "user-roles",
        context: CREDENTIALS,
        email: EMAIL,
        userId: "auth0|alice",
      })
    );

    expect(data.type).toBe("upstream_unavailable");
  });
});

describe("a lookup's failure", () => {
  /** Fails every Management API call but the user read. */
  const failingAfterTheUser = (status: number) =>
    auth0.intercept((call) =>
      call.path === "/oauth/token" ||
      isCall("GET", "/api/v2/users/auth0%7Calice")(call)
        ? undefined
        : failing(status)
    );

  it.each([
    { type: "users", email: EMAIL },
    { type: "roles" },
    { type: "apis" },
    { type: "permissions", resourceServerIdentifier: "urn:x" },
    { type: "organizations" },
    { type: "user-roles", email: EMAIL, userId: "auth0|alice" },
    {
      type: "user-permissions",
      email: EMAIL,
      userId: "auth0|alice",
      resourceServerIdentifier: "urn:x",
    },
    {
      type: "org-membership",
      email: EMAIL,
      userId: "auth0|alice",
      organizationId: "org_1",
    },
  ])("names the tenant, for $type", async (query) => {
    failingAfterTheUser(403);

    const data = await connectorError(() =>
      run({ ...query, context: CREDENTIALS } as ListerQuery)
    );

    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toMatchObject({ tenant: TENANT });
    expect(data.message).toContain(TENANT);
  });

  it.each([
    [{ type: "user-roles" }, "user auth0|alice"],
    [
      { type: "user-permissions", resourceServerIdentifier: "urn:x" },
      "user auth0|alice",
    ],
    [{ type: "org-membership", organizationId: "org_1" }, "organization org_1"],
  ] as const)("names what it couldn't find, for %o", async (query, subject) => {
    failingAfterTheUser(404);

    const data = await connectorError(() =>
      run({
        ...query,
        context: CREDENTIALS,
        email: EMAIL,
        userId: "auth0|alice",
      })
    );

    expect(data).toMatchObject({
      type: "object_not_found",
      payload: { query: subject },
    });
  });
});
