import { ConnectorError } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeCloud,
  failing,
  fakeEndpoint,
  newSeededCloud,
} from "../../__tests__/fake-cloud.ts";
import {
  CREDENTIALS,
  KEY_ID,
  KEY_SECRET,
  KEY_UUID,
  ORGANIZATION_ID,
  ORGANIZATION_NAME,
  SERVICE_ID,
} from "../../__tests__/fixtures.ts";
import { connectorError, newRecordingLogger } from "../../__tests__/helpers.ts";
import {
  RATE_LIMIT_BUDGET,
  forgetKeyUuids,
  newCloudClient,
  setPacing,
} from "../client.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const readApiKey = vi.hoisted(() => vi.fn());
vi.mock("../../secrets.ts", () => ({ readApiKey }));

const ORG = `/v1/organizations/${ORGANIZATION_ID}`;
const ENDPOINTS = `${ORG}/services/${SERVICE_ID}/query-api-endpoints`;

let fake: FakeCloud;
let logs: ReturnType<typeof newRecordingLogger>;

const client = () => newCloudClient({ ...CREDENTIALS, log: logs.log });

const REQUEST = {
  name: "p0_objects",
  sql: "SELECT 1",
  database: "system",
  parameters: {},
  apiKeyIds: [KEY_UUID],
  roles: ["sql_console_read_only"],
  allowedOrigins: [],
};

beforeEach(() => {
  fake = newSeededCloud();
  vi.stubGlobal("fetch", fake.fetch);
  logs = newRecordingLogger();
  forgetKeyUuids();
  readApiKey.mockReset();
  readApiKey.mockResolvedValue({
    keyId: KEY_ID,
    keySecret: KEY_SECRET,
    version: "1",
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("newCloudClient", () => {
  it("reads the key once, on its first call", async () => {
    const cloud = client();
    expect(readApiKey).not.toHaveBeenCalled();

    await cloud.getOrganization();
    await cloud.listServices();

    expect(readApiKey).toHaveBeenCalledTimes(1);
    expect(readApiKey).toHaveBeenCalledWith(CREDENTIALS.apiKeySecret);
  });

  it("reads the organization", async () => {
    await expect(client().getOrganization()).resolves.toEqual({
      id: ORGANIZATION_ID,
      name: ORGANIZATION_NAME,
    });
  });

  it("reads the members", async () => {
    fake.members.push({
      userId: "u-1",
      email: "alice@acme.com",
      name: "Alice",
    });

    await expect(client().listMembers()).resolves.toEqual([
      { userId: "u-1", email: "alice@acme.com", name: "Alice" },
    ]);
  });

  it("reads the services, with the fields the install reads", async () => {
    fake.services.push({
      id: "6a1f0e9d-8c7b-4a65-9b43-2a1f0e9d8c7b",
      name: "byoc",
      state: "idle",
      byocId: "byoc-1",
    });

    await expect(client().listServices()).resolves.toEqual([
      {
        id: SERVICE_ID,
        name: "prod",
        state: "running",
        clickhouseVersion: "26.4.1.1234",
      },
      {
        id: "6a1f0e9d-8c7b-4a65-9b43-2a1f0e9d8c7b",
        name: "byoc",
        state: "idle",
        byocId: "byoc-1",
      },
    ]);
  });

  it("reads one service", async () => {
    await expect(client().getService(SERVICE_ID)).resolves.toMatchObject({
      id: SERVICE_ID,
      name: "prod",
    });
  });

  it("lists the endpoints without their SQL, and reads one whole", async () => {
    const endpoint = fakeEndpoint({
      name: "p0_objects",
      apiKeyIds: [KEY_UUID],
    });
    fake.endpointsOf(SERVICE_ID).push(endpoint);
    const cloud = client();

    const [listed] = await cloud.listEndpoints(SERVICE_ID);
    expect(listed).not.toHaveProperty("sql");
    await expect(
      cloud.getEndpoint(SERVICE_ID, endpoint)
    ).resolves.toMatchObject({ sql: "SELECT 1", parameters: {} });
  });

  it("gives up on a listing past 100 pages", async () => {
    fake.intercept((call) =>
      call.path === ENDPOINTS && call.method === "GET"
        ? {
            status: 200,
            body: {
              result: [],
              nextCursor: "again",
              limit: 100,
              totalCount: null,
            },
          }
        : undefined
    );

    const data = await connectorError(() => client().listEndpoints(SERVICE_ID));

    expect(data.type).toBe("unknown");
    expect(fake.calls).toHaveLength(100);
  });

  it("creates, updates and deletes one of P0's endpoints", async () => {
    const cloud = client();

    const created = await cloud.createEndpoint(SERVICE_ID, REQUEST);
    const updated = await cloud.updateEndpoint(SERVICE_ID, created, {
      ...REQUEST,
      sql: "SELECT 2",
    });
    await cloud.deleteEndpoint(SERVICE_ID, created);

    expect(created.url).toBe(
      `https://queries.clickhouse.cloud/run/${created.id}`
    );
    expect(updated.sql).toBe("SELECT 2");
    expect(fake.endpointsOf(SERVICE_ID)).toEqual([]);
  });

  it.each([
    [
      "read",
      (c: ReturnType<typeof client>) => c.getEndpoint(SERVICE_ID, FOREIGN),
    ],
    [
      "create",
      (c: ReturnType<typeof client>) =>
        c.createEndpoint(SERVICE_ID, { ...REQUEST, name: "dashboard" }),
    ],
    [
      "update",
      (c: ReturnType<typeof client>) =>
        c.updateEndpoint(SERVICE_ID, FOREIGN, REQUEST),
    ],
    [
      "rename one of P0's to",
      (c: ReturnType<typeof client>) =>
        c.updateEndpoint(
          SERVICE_ID,
          { id: FOREIGN.id, name: "p0_objects" },
          { ...REQUEST, name: "dashboard" }
        ),
    ],
    [
      "delete",
      (c: ReturnType<typeof client>) => c.deleteEndpoint(SERVICE_ID, FOREIGN),
    ],
    [
      "run",
      (c: ReturnType<typeof client>) =>
        c.runEndpoint({
          name: "dashboard",
          url: `https://queries.clickhouse.cloud/run/${FOREIGN.id}`,
        }),
    ],
  ])(
    "refuses to %s an endpoint that isn't P0's, sending nothing",
    async (_case, act) => {
      const data = await connectorError(() => act(client()));

      expect(data.type).toBe("validation_error");
      expect(data.payload).not.toHaveProperty("reason");
      expect(fake.calls).toEqual([]);
    }
  );

  it("runs one of P0's endpoints, and returns its rows", async () => {
    fake.rows.set("p0_objects", [{ "1": 1 }]);
    const cloud = client();
    const ping = await cloud.createEndpoint(SERVICE_ID, REQUEST);

    await expect(cloud.runEndpoint(ping)).resolves.toEqual([{ "1": 1 }]);
  });

  describe("keyUuid", () => {
    const OTHER_UUID = "3e4f5a6b-7c8d-4e9f-a0b1-2c3d4e5f6a7b";

    it("finds the key whose suffix is its key ID's last 4 characters", async () => {
      await expect(client().keyUuid()).resolves.toBe(KEY_UUID);
    });

    it("finds the key whose suffix is its secret's last 4 characters", async () => {
      fake.keys.splice(0, fake.keys.length, {
        id: OTHER_UUID,
        name: "p0-connector",
        keySuffix: KEY_SECRET.slice(-4),
      });

      await expect(client().keyUuid()).resolves.toBe(OTHER_UUID);
    });

    it.each([
      [
        "no key matches",
        [{ id: OTHER_UUID, name: "other", keySuffix: "zz99" }],
        0,
      ],
      [
        "two keys match",
        [
          { id: KEY_UUID, name: "a", keySuffix: KEY_ID.slice(-4) },
          { id: OTHER_UUID, name: "b", keySuffix: KEY_SECRET.slice(-4) },
        ],
        2,
      ],
    ])(
      "fails as dependency_violation when %s, without quoting the secret",
      async (_case, keys, matches) => {
        fake.keys.splice(0, fake.keys.length, ...keys);

        const data = await connectorError(() => client().keyUuid());

        expect(data.type).toBe("dependency_violation");
        expect(data.message).toContain(
          "P0 couldn't tell which of the ClickHouse Cloud organization's API keys is its own"
        );
        expect(data.payload).toEqual({ matches, keys: keys.length });
        expect(JSON.stringify(data)).not.toContain(KEY_SECRET);
        expect(JSON.stringify(data)).not.toContain(KEY_SECRET.slice(-4));
      }
    );

    it("reads the client's last key listing rather than list the keys again", async () => {
      const cloud = client();
      await cloud.listKeys();

      await expect(cloud.keyUuid()).resolves.toBe(KEY_UUID);
      expect(
        fake.calls.filter(({ path }) => path.endsWith("/keys"))
      ).toHaveLength(1);
    });

    it("lists the keys once per key ID for the process's lifetime", async () => {
      await client().keyUuid();
      await client().keyUuid();

      expect(
        fake.calls.filter(({ path }) => path.endsWith("/keys"))
      ).toHaveLength(1);
    });

    // An organization pointed at another one's secret looks the key up among
    // its own keys, rather than reuse the other organization's UUID.
    it("keeps the UUID by organization and key ID", async () => {
      const other = "6f1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0b";
      await client().keyUuid();
      fake.intercept((call) =>
        call.method === "GET" && call.path === `/v1/organizations/${other}/keys`
          ? { status: 200, body: { status: 200, result: [] } }
          : undefined
      );

      const data = await connectorError(() =>
        newCloudClient({
          ...CREDENTIALS,
          organizationId: other,
          log: logs.log,
        }).keyUuid()
      );

      expect(data.type).toBe("dependency_violation");
      expect(
        fake.calls.filter(({ path }) => path.endsWith("/keys"))
      ).toHaveLength(2);
    });

    it("reads every page of the keys", async () => {
      fake = newSeededCloud({ pageSize: 1 });
      vi.stubGlobal("fetch", fake.fetch);
      fake.keys.reverse();

      await expect(client().keyUuid()).resolves.toBe(KEY_UUID);
      expect(
        fake.calls
          .filter(({ path }) => path.endsWith("/keys"))
          .map(({ query }) => query.cursor)
      ).toEqual([undefined, "1"]);
    });

    it("isn't kept when it fails", async () => {
      const keys = [...fake.keys];
      fake.keys.length = 0;
      await connectorError(() => client().keyUuid());
      fake.keys.push(...keys);

      await expect(client().keyUuid()).resolves.toBe(KEY_UUID);
    });
  });

  it("lists, creates, changes and deletes P0's roles", async () => {
    const cloud = client();
    const policy = {
      allowDeny: "ALLOW" as const,
      permissions: ["control-plane:organization:view"],
      resources: [`organization/${ORGANIZATION_ID}`],
    };

    const created = await cloud.createRole({
      name: "p0_ab12_alice_brave_otter",
      actors: [],
      policies: [policy],
    });
    const updated = await cloud.updateRole(created, {
      actors: ["user/u-1"],
    });
    expect(await cloud.listRoles()).toEqual([updated]);
    await cloud.deleteRole(created);

    expect(updated).toMatchObject({
      name: "p0_ab12_alice_brave_otter",
      actors: ["user/u-1"],
      policies: [policy],
    });
    expect(fake.roles).toEqual([]);
  });

  it.each([
    [
      "create",
      (c: ReturnType<typeof client>) =>
        c.createRole({ name: "Admin", actors: [], policies: [] }),
    ],
    [
      "change",
      (c: ReturnType<typeof client>) =>
        c.updateRole({ id: FOREIGN.id, name: "Admin" }, { actors: [] }),
    ],
    [
      "delete",
      (c: ReturnType<typeof client>) =>
        c.deleteRole({ id: FOREIGN.id, name: "Service admin" }),
    ],
  ])(
    "refuses to %s a role that isn't P0's, as not_p0_role",
    async (_case, act) => {
      const data = await connectorError(() => act(client()));

      expect(data.type).toBe("validation_error");
      expect(data.payload.reason).toBe("not_p0_role");
      expect(fake.calls).toEqual([]);
    }
  );

  describe.each([
    ["roles", "/roles", (c: ReturnType<typeof client>) => c.listRoles()],
    ["members", "/members", (c: ReturnType<typeof client>) => c.listMembers()],
    [
      "services",
      "/services",
      (c: ReturnType<typeof client>) => c.listServices(),
    ],
  ])("the %s listing, which the OpenAPI doesn't page", (listing, end, read) => {
    const answering = (page: Record<string, unknown>) =>
      fake.intercept((call) =>
        call.method === "GET" && call.path === `${ORG}${end}`
          ? { status: 200, body: { status: 200, result: [], ...page } }
          : undefined
      );

    it.each([
      ["a next cursor", { nextCursor: "2" }],
      ["a total past what it holds", { totalCount: 3 }],
    ])(
      "fails as unknown when it says it has more, by %s",
      async (_case, page) => {
        answering(page);

        expect(await connectorError(() => read(client()))).toEqual({
          type: "unknown",
          message: `ClickHouse Cloud paged the ${listing} listing, which P0 reads in one piece, so it can't tell what the later pages hold.`,
          payload: { what: `the organization's ${listing}` },
        });
        expect(fake.calls).toHaveLength(1);
      }
    );

    it("reads one that says it's whole", async () => {
      answering({ nextCursor: null, totalCount: 0 });

      await expect(read(client())).resolves.toEqual([]);
    });
  });

  describe("listRoles, on a role it can't read", () => {
    const P0_ROLE = "p0_ab12_alice_brave_otter";

    const listing = (...result: unknown[]) =>
      fake.intercept((call) =>
        call.method === "GET" && call.path === `${ORG}/roles`
          ? { status: 200, body: { status: 200, result } }
          : undefined
      );

    const readable = {
      id: "r-ok",
      name: P0_ROLE,
      type: "custom",
      actors: null,
      policies: [
        {
          allowDeny: "ALLOW",
          permissions: ["control-plane:service:view"],
          resources: [`instance/${SERVICE_ID}`],
          tags: { grants: null, roleV2: null },
        },
      ],
    };

    const unreadable = (name: unknown, type = "custom") => ({
      id: "r-odd",
      name,
      type,
      actors: [],
      policies: [{ allowDeny: "MAYBE", permissions: [], resources: [] }],
    });

    it("reads null fields as empty", async () => {
      listing(readable);

      await expect(client().listRoles()).resolves.toEqual([
        {
          id: "r-ok",
          name: P0_ROLE,
          type: "custom",
          actors: [],
          policies: [
            {
              allowDeny: "ALLOW",
              permissions: ["control-plane:service:view"],
              resources: [`instance/${SERVICE_ID}`],
              tags: {},
            },
          ],
        },
      ]);
    });

    it.each([
      ["a customer's custom role", unreadable("analysts")],
      ["a system role it wasn't asked for", unreadable("Admin", "system")],
      // Otherwise one odd P0 role would stop every revoke in the organization.
      ["another request's P0 role", unreadable("p0_cd34_bob_calm_heron")],
    ])("drops %s, logging its ID only", async (_case, odd) => {
      listing(readable, odd);

      expect(await client().listRoles({ target: P0_ROLE })).toHaveLength(1);
      expect(logs.warn).toHaveBeenCalledWith(
        { roleId: "r-odd" },
        "dropped a role the connector can't read"
      );
    });

    it.each([
      [
        "the role it acts on",
        unreadable("p0_cd34_bob_calm_heron"),
        "the role p0_cd34_bob_calm_heron",
      ],
      ["one without a name", unreadable(7), "a role"],
      [
        "a system role it was asked for",
        unreadable("Service Admin", "system"),
        "the role Service Admin",
      ],
      [
        "a system role it was asked for, in another case",
        unreadable("service admin", "system"),
        "the role service admin",
      ],
    ])("fails as unknown on %s", async (_case, odd, named) => {
      listing(readable, odd);

      expect(
        await connectorError(() =>
          client().listRoles({
            target: "p0_cd34_bob_calm_heron",
            systemRoles: ["Service Admin"],
          })
        )
      ).toEqual({
        type: "unknown",
        message: `ClickHouse Cloud returned ${named} in a shape P0 doesn't recognize.`,
        payload: { what: "the organization's roles" },
      });
    });
  });

  it("fails as unknown on a shape it doesn't know", async () => {
    fake.intercept(() => ({ status: 200, body: { result: { id: 7 } } }));

    const data = await connectorError(() => client().getOrganization());

    expect(data).toEqual({
      type: "unknown",
      message:
        "ClickHouse Cloud returned the organization in a shape P0 doesn't recognize.",
      payload: { what: "the organization" },
    });
  });

  it("throws a refused call as a ClickHouseError, for the caller to map", async () => {
    fake.state.permissions.clear();

    const error = await client()
      .listMembers()
      .catch((e: unknown) => e);

    expect(error).not.toBeInstanceOf(ConnectorError);
    expect(error).toMatchObject({ name: "ClickHouseError", status: 403 });
  });

  describe("the rate limit", () => {
    const cloudCalls = () =>
      fake.calls.filter(({ host }) => host === "api.clickhouse.cloud");

    beforeEach(() => {
      vi.useFakeTimers();
      setPacing(true);
    });

    afterEach(() => {
      setPacing(false);
      vi.useRealTimers();
    });

    it("sends at most 10 Cloud API calls in a window, and the 11th once the window has passed", async () => {
      const cloud = client();

      const answers = Promise.all(
        Array.from({ length: 11 }, () => cloud.getOrganization())
      );
      await vi.advanceTimersByTimeAsync(0);
      expect(cloudCalls()).toHaveLength(10);

      await vi.advanceTimersByTimeAsync(10_999);
      expect(cloudCalls()).toHaveLength(10);

      await vi.advanceTimersByTimeAsync(1);
      expect(cloudCalls()).toHaveLength(11);
      await expect(answers).resolves.toHaveLength(11);
    });

    it("doesn't pace runs of Query API endpoints", async () => {
      const cloud = client();
      const ping = await cloud.createEndpoint(SERVICE_ID, REQUEST);

      const rows = Promise.all(
        Array.from({ length: 11 }, () => cloud.runEndpoint(ping))
      );
      await vi.advanceTimersByTimeAsync(0);

      await expect(rows).resolves.toHaveLength(11);
    });

    it.each([
      ["Retry-After says", { "retry-after": "7" }, 7_000],
      ["Retry-After is absent, 10 seconds", undefined, 10_000],
    ])(
      "sends a call again after a 429, waiting as long as %s",
      async (_case, headers, wait) => {
        let refused = false;
        fake.intercept(() => {
          if (refused) return undefined;
          refused = true;
          return failing(429, "Too Many Requests", headers);
        });
        const organization = client().getOrganization();

        await vi.advanceTimersByTimeAsync(wait - 1);
        expect(cloudCalls()).toHaveLength(1);

        await vi.advanceTimersByTimeAsync(1);
        expect(cloudCalls()).toHaveLength(2);
        await expect(organization).resolves.toEqual({
          id: ORGANIZATION_ID,
          name: ORGANIZATION_NAME,
        });
      }
    );

    it("gives up on a 429 once its wait would end past the budget, with Retry-After", async () => {
      fake.intercept(() =>
        failing(429, "Too Many Requests", { "retry-after": "100" })
      );

      const error = client()
        .getOrganization()
        .catch((e: unknown) => e);
      await vi.advanceTimersByTimeAsync(RATE_LIMIT_BUDGET);

      // At 0, 100 and 200 seconds. A wait from 200 would end at 300.
      expect(cloudCalls()).toHaveLength(3);
      await expect(error).resolves.toMatchObject({
        name: "ClickHouseError",
        status: 429,
        retryAfter: "100",
      });
    });

    it("fails as rate_limited when a call's turn would come past the budget", async () => {
      const cloud = client();
      await vi.advanceTimersByTimeAsync(RATE_LIMIT_BUDGET - 5_000);

      const answers = Array.from({ length: 11 }, () =>
        connectorError(() => cloud.getOrganization()).catch(
          (error: unknown) => error
        )
      );
      await vi.advanceTimersByTimeAsync(0);

      expect(cloudCalls()).toHaveLength(10);
      await expect(answers[10]).resolves.toEqual({
        type: "rate_limited",
        message:
          "ClickHouse Cloud rate-limits P0's API key to 10 requests per 10 seconds, and this needs more calls than P0 can send in the time it has. Retry in a few minutes. If it keeps happening, a large organization can ask ClickHouse support to raise the key's limit.",
        payload: { organizationId: ORGANIZATION_ID },
      });
    });
  });
});

const FOREIGN = {
  id: "2d3e4f5a-6b7c-4d8e-9fa0-1b2c3d4e5f6a",
  name: "dashboard",
};
