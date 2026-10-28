import { createLogger } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeAccount,
  databricks,
  fakeAccount,
  grantsKey,
} from "../../../__tests__/databricks.ts";
import {
  ACCOUNT_API,
  ACCOUNT_ID,
  APPLICATION_ID,
  DEPLOYMENT_NAME,
  SP_SCIM_ID,
  WORKSPACE_ID,
  WORKSPACE_URL,
  accountContext,
  databricksCalls,
  resetBetweenTests,
  stubFetch,
} from "../../../__tests__/http.ts";
import { resetWorkspaceCache } from "../../../databricks/workspaces.ts";
import { connectorRouter } from "../../../router.ts";
import type {
  ListerQuery,
  Policy,
  RequestContext,
  RequestGrant,
} from "../definition.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);

const { mockedSleep } = vi.hoisted(() => ({
  mockedSleep: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("node:timers/promises", () => ({ setTimeout: mockedSleep }));

resetBetweenTests();

const NAME = "p0-agent-req_123";
const AGENT_ID = "8100000000000001";
const AGENT = "3a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const WAREHOUSE_ID = "abc123def456";
const OWNER = "data-admins";

/** The grants a `read` request on schema `main.sales` adds. */
const READ_SALES: RequestGrant[] = [
  { securableType: "catalog", fullName: "main", privilege: "USE_CATALOG" },
  { securableType: "schema", fullName: "main.sales", privilege: "USE_SCHEMA" },
  { securableType: "schema", fullName: "main.sales", privilege: "SELECT" },
];

/** The grants of a request on schema `main.sales` that also lets the agent create tables. */
const WRITE_SALES: RequestGrant[] = [
  ...READ_SALES,
  {
    securableType: "schema",
    fullName: "main.sales",
    privilege: "CREATE_TABLE",
  },
];

const context = (overrides: Partial<RequestContext> = {}): RequestContext => ({
  ...accountContext(),
  workspaceId: WORKSPACE_ID,
  agentApplicationId: AGENT,
  federation: {
    issuer: "https://p0.example.com/oauth",
    subject: "mcps/databricksSql/abc123",
  },
  warehouseId: WAREHOUSE_ID,
  securable: { type: "schema", fullName: "main.sales" },
  addedGrants: WRITE_SALES,
  ownerPrincipal: OWNER,
  ...overrides,
});

const policies = WRITE_SALES as Policy[];

let account: FakeAccount;

beforeEach(() => {
  mockedSleep.mockClear();
  account = fakeAccount();
  account.servicePrincipals.push({
    id: AGENT_ID,
    applicationId: AGENT,
    displayName: NAME,
    active: true,
  });
  account.warehouses = [
    { id: WAREHOUSE_ID, name: "Analytics", warehouse_type: "PRO" },
    { id: "classic1", name: "Old", warehouse_type: "CLASSIC" },
  ];
  account.uc = {
    catalogs: ["main", "system", "__databricks_internal"],
    schemas: [
      { catalog: "main", name: "sales" },
      { catalog: "main", name: "ops" },
    ],
    objects: [
      {
        kind: "tables",
        catalog: "main",
        schema: "sales",
        name: "orders",
        owner: "alice@example.com",
      },
    ],
  };
});

const data = () =>
  connectorRouter.createCaller({ logger: createLogger() })["databricks-ai"]
    .accesses.data;

const provision = (overrides: Partial<RequestContext> = {}) =>
  data().provisionUser({ userBody: NAME, context: context(overrides) });
const identify = (overrides: Partial<RequestContext> = {}) =>
  data().identifyUser({ userBody: NAME, context: context(overrides) });
const setPolicies = (
  granted: Policy[],
  overrides: Partial<RequestContext> = {}
) =>
  data().setPoliciesForUser({
    userId: NAME,
    userBody: NAME,
    policies: granted,
    context: context(overrides),
  });
const remove = (overrides: Partial<RequestContext> = {}) =>
  data().deleteUser({
    userId: NAME,
    userBody: NAME,
    context: context(overrides),
  });
const list = (query: ListerQuery) => data().list({ query });

const held = (type: string, fullName: string, principal = AGENT) =>
  account.grants[grantsKey(type, fullName)]?.[principal.toLowerCase()] ?? [];

/** Everything the agent holds anywhere, ignoring empty entries. */
const agentGrants = () =>
  Object.entries(account.grants).flatMap(([key, byPrincipal]) =>
    (byPrincipal[AGENT.toLowerCase()] ?? []).map(
      (privilege) => `${privilege}@${key}`
    )
  );

const agentCanUse = () =>
  (account.warehouseAcl[WAREHOUSE_ID] ?? []).some(
    (entry) =>
      entry.service_principal_name === AGENT &&
      entry.permission_level === "CAN_USE"
  );

/** A finished grant: the principal set up and granted `WRITE_SALES`. */
const granted = async () => {
  await provision();
  await setPolicies(policies);
};

/** The app's revoke: `identifyUser`, `setPoliciesForUser([])`, `identifyUser`, `deleteUser`, each skipped after a `null`. */
const appRevoke = async () => {
  const errors: unknown[] = [];
  // Every down step runs even when an earlier one failed.
  const step = async (run: () => Promise<unknown>) => {
    try {
      await run();
    } catch (error) {
      errors.push(error);
    }
  };
  await step(async () => {
    if ((await identify()) !== null) await setPolicies([]);
  });
  await step(async () => {
    if ((await identify()) !== null) await remove();
  });
  if (errors.length > 0) throw errors[0];
};

describe("setPoliciesForUser, grant", () => {
  it("grants the warehouse and the policies, and reads them back", async () => {
    stubFetch(databricks(account));
    await provision();
    const fetchMock = stubFetch(databricks(account));

    await setPolicies(policies);

    expect(agentCanUse()).toBe(true);
    expect(agentGrants()).toEqual([
      "USE_CATALOG@catalog:main",
      "USE_SCHEMA@schema:main.sales",
      "SELECT@schema:main.sales",
      "CREATE_TABLE@schema:main.sales",
    ]);
    // Nothing on system.ai: agents call the MCP services through the
    // account users' default EXECUTE there.
    expect(held("schema", "system.ai", APPLICATION_ID)).toEqual([]);

    const patches = databricksCalls(fetchMock)
      .filter(({ init }) => init.method === "PATCH")
      .map(({ url, init }) => [
        new URL(url).pathname,
        JSON.parse(init.body ?? ""),
      ]);
    expect(patches).toEqual([
      [
        `/api/2.0/permissions/warehouses/${WAREHOUSE_ID}`,
        {
          access_control_list: [
            { service_principal_name: AGENT, permission_level: "CAN_USE" },
          ],
        },
      ],
      [
        "/api/2.1/unity-catalog/permissions/catalog/main",
        { changes: [{ principal: AGENT, add: ["USE_CATALOG"] }] },
      ],
      [
        "/api/2.1/unity-catalog/permissions/schema/main.sales",
        {
          changes: [
            { principal: AGENT, add: ["USE_SCHEMA", "SELECT", "CREATE_TABLE"] },
          ],
        },
      ],
    ]);
    // Every call went to the workspace P0 built from the account API.
    expect(
      databricksCalls(fetchMock)
        .filter(({ init }) => init.method === "PATCH")
        .every(({ url }) => url.startsWith(WORKSPACE_URL))
    ).toBe(true);
  });

  it("refuses P0's own principal, before calling anything", async () => {
    const fetchMock = stubFetch(databricks(account));

    await expect(
      setPolicies(policies, { agentApplicationId: APPLICATION_ID })
    ).rejects.toMatchObject({
      message:
        "P0 cannot grant access to its own Databricks service principal.",
      data: { type: "validation_error" },
    });
    expect(databricksCalls(fetchMock)).toEqual([]);
  });

  it("is safe to repeat", async () => {
    stubFetch(databricks(account));
    await granted();
    stubFetch(databricks(account));

    await setPolicies(policies);

    expect(held("schema", "main.sales")).toEqual([
      "USE_SCHEMA",
      "SELECT",
      "CREATE_TABLE",
    ]);
  });

  it("refuses a policy that isn't one of the request's added grants, before calling anything", async () => {
    const fetchMock = stubFetch(databricks(account));

    await expect(
      setPolicies([
        ...policies,
        { securableType: "catalog", fullName: "main", privilege: "MODIFY" },
      ])
    ).rejects.toMatchObject({
      message:
        "A grant's policies must all be in its added grants, but these aren't: MODIFY@catalog:main.",
      data: { type: "validation_error" },
    });
    expect(databricksCalls(fetchMock)).toEqual([]);
  });

  it("refuses a privilege outside the levels in a policy", async () => {
    stubFetch(databricks(account));

    await expect(
      setPolicies([
        { securableType: "catalog", fullName: "main", privilege: "MANAGE" },
      ] as unknown as Policy[])
    ).rejects.toThrow();
  });

  it("fails when the read-back doesn't match", async () => {
    stubFetch((url, init) => {
      const response = databricks(account)(url, init);
      // Databricks drops the schema grant as soon as it is made.
      if (init.method === "PATCH" && url.includes("/schema/main.sales")) {
        account.grants[grantsKey("schema", "main.sales")] = {};
      }
      return response;
    });
    await provision();

    await expect(setPolicies(policies)).rejects.toMatchObject({
      message: `Databricks permissions for ${AGENT} don't match after the grant: schema main.sales is missing USE_SCHEMA, SELECT, CREATE_TABLE`,
      data: { type: "dependency_violation" },
    });
  });

  it("leaves a principal Databricks doesn't know yet as a plain, retryable failure", async () => {
    stubFetch(databricks(account));
    await provision();
    account.fail["PATCH /api/2.1/unity-catalog/permissions/catalog/main"] = {
      status: 400,
      errorCode: "PRINCIPAL_DOES_NOT_EXIST",
    };

    await expect(setPolicies(policies)).rejects.toMatchObject({
      message: expect.stringContaining("(400)"),
    });
  });
});

describe("setPoliciesForUser, revoke", () => {
  it("deactivates the principal, removes its grants, and transfers what it owns", async () => {
    stubFetch(databricks(account));
    await granted();
    account.uc.objects.push(
      {
        kind: "tables",
        catalog: "main",
        schema: "sales",
        name: "summary",
        owner: AGENT,
      },
      {
        kind: "volumes",
        catalog: "main",
        schema: "sales",
        name: "exports",
        owner: AGENT,
      },
      {
        kind: "functions",
        catalog: "main",
        schema: "sales",
        name: "score",
        owner: AGENT,
      }
    );
    const fetchMock = stubFetch(databricks(account));

    await setPolicies([]);

    expect(
      account.servicePrincipals.find(({ id }) => id === AGENT_ID)?.active
    ).toBe(false);
    expect(agentGrants()).toEqual([]);
    expect(account.uc.objects.map(({ name, owner }) => [name, owner])).toEqual([
      ["orders", "alice@example.com"],
      ["summary", OWNER],
      ["exports", OWNER],
      ["score", OWNER],
    ]);
    // The warehouse grant stays until the principal is deleted, because
    // removing one entry means rewriting the warehouse's whole access list.
    expect(agentCanUse()).toBe(true);

    const deactivate = databricksCalls(fetchMock).find(
      ({ url, init }) => init.method === "PATCH" && url.startsWith(ACCOUNT_API)
    );
    expect(deactivate?.url).toBe(
      `${ACCOUNT_API}/scim/v2/ServicePrincipals/${AGENT_ID}`
    );
    expect(JSON.parse(deactivate?.init.body ?? "")).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [
        { op: "replace", path: "active", value: [{ value: "false" }] },
      ],
    });
    // Revoking runs before the transfer, leaves first.
    const writes = databricksCalls(fetchMock)
      .filter(({ init }) => init.method === "PATCH")
      .map(({ url }) => new URL(url).pathname.replace(/^\/api\/2\.\d\//, ""));
    expect(writes).toEqual([
      `accounts/${ACCOUNT_ID}/scim/v2/ServicePrincipals/${AGENT_ID}`,
      "unity-catalog/permissions/schema/main.sales",
      "unity-catalog/permissions/catalog/main",
      "unity-catalog/tables/main.sales.summary",
      "unity-catalog/volumes/main.sales.exports",
      "unity-catalog/functions/main.sales.score",
    ]);
  });

  it("revokes an agent granted when the context named an MCP service, touching no MCP service", async () => {
    stubFetch(databricks(account));
    await granted();
    const fetchMock = stubFetch(databricks(account));
    const before = { ...context(), mcpService: "system.ai.dbsql" };

    await data().setPoliciesForUser({
      userId: NAME,
      userBody: NAME,
      policies: [],
      context: before,
    });

    expect(agentGrants()).toEqual([]);
    expect(
      databricksCalls(fetchMock).filter(({ url }) =>
        url.includes("mcp_service")
      )
    ).toEqual([]);
  });

  it("transfers from every schema under a catalog", async () => {
    stubFetch(databricks(account));
    await granted();
    account.uc.objects.push({
      kind: "tables",
      catalog: "main",
      schema: "ops",
      name: "runs",
      owner: AGENT,
    });

    await setPolicies([], { securable: { type: "catalog", fullName: "main" } });

    expect(account.uc.objects.find(({ name }) => name === "runs")?.owner).toBe(
      OWNER
    );
  });

  it.each([
    ["table", "main.sales.orders", "tables"],
    ["volume", "main.sales.exports", "volumes"],
  ] as const)(
    "transfers a %s securable it owns",
    async (type, fullName, kind) => {
      account.uc.objects = [
        {
          kind,
          catalog: "main",
          schema: "sales",
          name: fullName.split(".")[2] ?? "",
          owner: AGENT,
        },
      ];
      stubFetch(databricks(account));

      await setPolicies([], { securable: { type, fullName } });

      expect(account.uc.objects[0]?.owner).toBe(OWNER);
    }
  );

  it("counts a dropped securable as done", async () => {
    stubFetch(databricks(account));
    await granted();
    account.uc.schemas = account.uc.schemas.filter(
      ({ name }) => name !== "sales"
    );

    await expect(setPolicies([])).resolves.toBeNull();
    expect(held("catalog", "main")).toEqual([]);
  });

  it("counts a principal the metastore no longer knows as done", async () => {
    stubFetch(databricks(account));
    await granted();
    account.servicePrincipals = account.servicePrincipals.filter(
      ({ id }) => id !== AGENT_ID
    );

    await expect(setPolicies([])).resolves.toBeNull();
  });

  it("attempts every removal and the transfer, then throws the first failure", async () => {
    stubFetch(databricks(account));
    await granted();
    account.uc.objects.push({
      kind: "tables",
      catalog: "main",
      schema: "sales",
      name: "summary",
      owner: AGENT,
    });
    account.fail["PATCH /api/2.1/unity-catalog/permissions/schema/main.sales"] =
      500;

    await expect(setPolicies([])).rejects.toMatchObject({
      message: expect.stringContaining(
        "PATCH /api/2.1/unity-catalog/permissions/schema/main.sales failed (500)"
      ),
    });
    expect(held("catalog", "main")).toEqual([]);
    expect(
      account.uc.objects.find(({ name }) => name === "summary")?.owner
    ).toBe(OWNER);
  });

  it("still removes every grant when the deactivation fails, then throws its failure", async () => {
    stubFetch(databricks(account));
    await granted();
    account.fail[
      `PATCH /api/2.0/accounts/${ACCOUNT_ID}/scim/v2/ServicePrincipals/${AGENT_ID}`
    ] = 500;

    await expect(setPolicies([])).rejects.toMatchObject({
      message: expect.stringContaining(
        `/scim/v2/ServicePrincipals/${AGENT_ID} failed (500)`
      ),
    });
    expect(agentGrants()).toEqual([]);
  });

  it("still removes every grant when the principal's lookup fails, then throws its failure", async () => {
    stubFetch(databricks(account));
    await granted();
    account.fail[
      `GET /api/2.0/accounts/${ACCOUNT_ID}/scim/v2/ServicePrincipals`
    ] = 503;

    await expect(setPolicies([])).rejects.toMatchObject({
      message: expect.stringContaining("failed (503)"),
    });
    expect(agentGrants()).toEqual([]);
  });

  it("skips the transfer when the request added no CREATE privilege", async () => {
    stubFetch(databricks(account));
    await granted();
    account.uc.objects.push({
      kind: "tables",
      catalog: "main",
      schema: "sales",
      name: "summary",
      owner: AGENT,
    });
    const fetchMock = stubFetch(databricks(account));

    await setPolicies([], { addedGrants: READ_SALES });

    expect(
      account.uc.objects.find(({ name }) => name === "summary")?.owner
    ).toBe(AGENT);
    expect(
      databricksCalls(fetchMock).some(({ url }) =>
        new URL(url).pathname.startsWith("/api/2.1/unity-catalog/tables")
      )
    ).toBe(false);
  });

  it("revokes on a workspace that isn't running, since the grants are on the metastore", async () => {
    stubFetch(databricks(account));
    await granted();
    account.workspaces = [
      { ...account.workspaces[0], workspace_status: "FAILED" },
    ];
    resetWorkspaceCache();

    await expect(setPolicies([])).resolves.toBeNull();
    expect(agentGrants()).toEqual([]);
  });

  it("fails on a deleted workspace, which it can't revoke through, saying how to remove the grants by hand", async () => {
    stubFetch(databricks(account));
    await granted();
    account.workspaces = [];
    resetWorkspaceCache();

    await expect(setPolicies([])).rejects.toMatchObject({
      message: `Databricks account ${ACCOUNT_ID} has no workspace ${WORKSPACE_ID}, so P0 can't revoke service principal ${NAME} (${AGENT}) through it. Its grants are on the workspace's metastore and stay there. To remove them, have a metastore admin work from another workspace on the same metastore. First hand anything that principal owns to ${OWNER}, then revoke every privilege it holds. Last, delete service principal ${NAME} in the account console.`,
      data: { type: "object_not_found" },
    });
  });
});

describe("deleteUser", () => {
  it("revokes, then deletes the policy and the principal", async () => {
    stubFetch(databricks(account));
    await granted();

    await remove();

    expect(account.servicePrincipals.map(({ id }) => id)).toEqual([SP_SCIM_ID]);
    expect(agentGrants()).toEqual([]);
    expect(account.policies[AGENT_ID]).toBeUndefined();
  });

  it("deletes nothing when the ownership transfer fails", async () => {
    stubFetch(databricks(account));
    await granted();
    account.uc.objects.push({
      kind: "tables",
      catalog: "main",
      schema: "sales",
      name: "summary",
      owner: AGENT,
    });
    account.fail["PATCH /api/2.1/unity-catalog/tables/main.sales.summary"] =
      500;

    await expect(setPolicies([])).rejects.toThrow();
    await expect(remove()).rejects.toThrow();

    expect(account.servicePrincipals.map(({ id }) => id)).toContain(AGENT_ID);
    expect(account.policies[AGENT_ID]).toHaveLength(1);
    // Revoking ran first, so no grant is left while the transfer waits.
    expect(agentGrants()).toEqual([]);
  });
});

describe("revoke retries", () => {
  const steps = [
    `PATCH /api/2.0/accounts/${ACCOUNT_ID}/scim/v2/ServicePrincipals/${AGENT_ID}`,
    "PATCH /api/2.1/unity-catalog/permissions/schema/main.sales",
    "GET /api/2.1/unity-catalog/tables",
    "PATCH /api/2.1/unity-catalog/tables/main.sales.summary",
    `DELETE /api/2.0/accounts/${ACCOUNT_ID}/servicePrincipals/${AGENT_ID}/federationPolicies/p0-databricks`,
    `DELETE /api/2.0/accounts/${ACCOUNT_ID}/scim/v2/ServicePrincipals/${AGENT_ID}`,
  ];

  it.each(steps)(
    "finishes on a retry after %s fails, with every step run twice",
    async (call) => {
      stubFetch(databricks(account));
      await granted();
      account.uc.objects.push({
        kind: "tables",
        catalog: "main",
        schema: "sales",
        name: "summary",
        owner: AGENT,
      });

      account.fail[call] = 500;
      await expect(appRevoke()).rejects.toThrow();
      delete account.fail[call];

      // Dev and stage run every step twice in a row.
      await appRevoke();
      await appRevoke();

      expect(account.servicePrincipals.map(({ id }) => id)).toEqual([
        SP_SCIM_ID,
      ]);
      expect(agentGrants()).toEqual([]);
      expect(
        account.uc.objects.find(({ name }) => name === "summary")?.owner
      ).toBe(OWNER);
      await expect(identify()).resolves.toBeNull();
    }
  );
});

describe("list", () => {
  const ctx = accountContext();

  it("lists running workspaces with their host, skipping any whose host P0 can't build", async () => {
    account.workspaces = [
      ...account.workspaces,
      {
        workspace_id: 2,
        workspace_name: "staging",
        deployment_name: "dbc-staging",
        workspace_status: "PROVISIONING",
      },
      {
        workspace_id: 3,
        workspace_name: "odd",
        deployment_name: "evil.example.com/",
        workspace_status: "RUNNING",
      },
    ];
    const fetchMock = stubFetch(databricks(account));

    await expect(list({ type: "workspaces", context: ctx })).resolves.toEqual([
      {
        key: WORKSPACE_ID,
        value: `analytics (https://${DEPLOYMENT_NAME}.cloud.databricks.com)`,
      },
    ]);
    // Listing workspaces makes P0 admin of none of them.
    expect(
      databricksCalls(fetchMock).every(({ init }) => init.method === "GET")
    ).toBe(true);
  });

  it("returns one workspace's host as one item", async () => {
    stubFetch(databricks(account));

    await expect(
      list({ type: "workspace", context: ctx, workspaceId: WORKSPACE_ID })
    ).resolves.toEqual([{ key: WORKSPACE_ID, value: WORKSPACE_URL }]);
  });

  it("lists only pro and serverless warehouses, after making P0 workspace admin", async () => {
    stubFetch(databricks(account));

    await expect(
      list({ type: "warehouses", context: ctx, workspaceId: WORKSPACE_ID })
    ).resolves.toEqual([{ key: WAREHOUSE_ID, value: "Analytics" }]);
    expect(
      account.assignments.find(
        (a) => String(a.principal.principal_id) === SP_SCIM_ID
      )?.permissions
    ).toEqual(["ADMIN"]);
  });

  const WAREHOUSES = "/api/2.0/sql/warehouses";

  it("tries again while the workspace hasn't seen P0's new admin assignment", async () => {
    let tries = 0;
    stubFetch((url, init) => {
      if (new URL(url).pathname === WAREHOUSES && ++tries === 1) {
        account.fail[`GET ${WAREHOUSES}`] = 403;
      } else {
        delete account.fail[`GET ${WAREHOUSES}`];
      }
      return databricks(account)(url, init);
    });

    await expect(
      list({ type: "warehouses", context: ctx, workspaceId: WORKSPACE_ID })
    ).resolves.toEqual([{ key: WAREHOUSE_ID, value: "Analytics" }]);
    expect(tries).toBe(2);
    expect(mockedSleep).toHaveBeenCalledTimes(1);
  });

  it("fails as retryable when the workspace keeps refusing P0's new admin assignment", async () => {
    account.fail[`GET ${WAREHOUSES}`] = 401;
    stubFetch(databricks(account));

    await expect(
      list({ type: "warehouses", context: ctx, workspaceId: WORKSPACE_ID })
    ).rejects.toMatchObject({
      message: `Databricks hasn't seen P0's new workspace admin assignment in workspace ${WORKSPACE_ID} yet. Try again in a few minutes.`,
      data: { type: "upstream_unavailable" },
    });
    // 30 s in all, well inside the 270 s Lambda.
    const waited = mockedSleep.mock.calls.reduce(
      (total, [delay]) => total + Number(delay),
      0
    );
    expect(waited).toBe(30_000);
  });

  it("doesn't try again when P0 was already workspace admin", async () => {
    account.assignments.push({
      principal: { principal_id: Number(SP_SCIM_ID) },
      permissions: ["ADMIN"],
    });
    account.fail[`GET ${WAREHOUSES}`] = 403;
    stubFetch(databricks(account));

    await expect(
      list({ type: "warehouses", context: ctx, workspaceId: WORKSPACE_ID })
    ).rejects.toMatchObject({
      message: expect.stringContaining(`GET ${WAREHOUSES} failed (403)`),
    });
    expect(mockedSleep).not.toHaveBeenCalled();
  });

  it("hides the system and Databricks-internal catalogs", async () => {
    stubFetch(databricks(account));

    await expect(
      list({ type: "catalogs", context: ctx, workspaceId: WORKSPACE_ID })
    ).resolves.toEqual([{ key: "main", value: "main" }]);
  });

  it("lists schemas, tables and volumes", async () => {
    account.uc.objects.push({
      kind: "volumes",
      catalog: "main",
      schema: "sales",
      name: "exports",
      owner: "alice@example.com",
    });
    stubFetch(databricks(account));
    const workspaceId = WORKSPACE_ID;

    await expect(
      list({ type: "schemas", context: ctx, workspaceId, catalog: "main" })
    ).resolves.toEqual([
      { key: "sales", value: "sales" },
      { key: "ops", value: "ops" },
    ]);
    await expect(
      list({
        type: "tables",
        context: ctx,
        workspaceId,
        catalog: "main",
        schema: "sales",
      })
    ).resolves.toEqual([{ key: "orders", value: "orders" }]);
    await expect(
      list({
        type: "volumes",
        context: ctx,
        workspaceId,
        catalog: "main",
        schema: "sales",
      })
    ).resolves.toEqual([{ key: "exports", value: "exports" }]);
  });
});

describe("namespace", () => {
  it("refuses a user outside p0-agent-", async () => {
    const fetchMock = stubFetch(databricks(account));

    await expect(
      data().setPoliciesForUser({
        userId: "alice",
        userBody: "alice",
        policies: [],
        context: context(),
      })
    ).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
