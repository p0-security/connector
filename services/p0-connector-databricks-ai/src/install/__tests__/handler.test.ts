import { createLogger } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeAccount,
  OWN_PRINCIPAL,
  databricks,
  fakeAccount,
} from "../../__tests__/databricks.ts";
import {
  ACCOUNTS_URL,
  ACCOUNT_API,
  ACCOUNT_ID,
  APPLICATION_ID,
  DEPLOYMENT_NAME,
  SP_SCIM_ID,
  WORKSPACE_ID,
  WORKSPACE_URL,
  accountContext,
  databricksCalls,
  fetchCalls,
  jsonResponse,
  resetBetweenTests,
  stubFetch,
} from "../../__tests__/http.ts";
import { connectorRouter } from "../../router.ts";
import type { InstallValidationInput, ProbeInput } from "../definition.ts";
import { DBSQL_MCP_PATH, MCP_ACCEPT } from "../probe.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);

resetBetweenTests();

/** What Databricks holds, reset before each test. */
let account: FakeAccount;

beforeEach(() => {
  account = fakeAccount();
});

// Calling through the connector router also proves the `databricks-ai`
// namespace is registered with its install router.
const caller = () =>
  connectorRouter.createCaller({ logger: createLogger() })["databricks-ai"]
    .install.validation;

const validate = (input: InstallValidationInput) => caller().get(input);

const probe = (input: Partial<ProbeInput> = {}) =>
  caller().probe({ ...accountContext(), workspaceId: WORKSPACE_ID, ...input });

const servicePrincipal = {
  id: SP_SCIM_ID,
  applicationId: APPLICATION_ID,
  displayName: "p0-connector",
};

const notAccountAdmin = {
  message: `Service principal ${APPLICATION_ID} is not an account admin in Databricks account ${ACCOUNT_ID}. Check that the account's Terraform, which gives it that role, is applied.`,
  data: { type: "insufficient_privileges" },
};

const metastoreRemedy = `Make service principal ${APPLICATION_ID}, or a group it is a direct member of, the metastore's owner.`;

const METASTORE_ID = "11111111-aaaa-4bbb-8ccc-222222222222";

describe("install validation get", () => {
  describe("signing in", () => {
    it("only exchanges a token when no check is asked for", async () => {
      const fetchMock = stubFetch(databricks(account));

      await expect(validate(accountContext())).resolves.toEqual({
        servicePrincipal: null,
        metastores: null,
        ownerPrincipal: null,
      });

      expect(fetchCalls(fetchMock).map(({ url }) => url)).toEqual([
        `${ACCOUNTS_URL}/oidc/accounts/${ACCOUNT_ID}/v1/token`,
      ]);
    });

    it("fails when the token exchange is refused", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () =>
          jsonResponse(
            { error: "invalid_request", error_description: "no policy" },
            { status: 401 }
          )
        )
      );

      await expect(validate(accountContext())).rejects.toMatchObject({
        message: expect.stringContaining(
          `Check that the federation policy of service principal ${APPLICATION_ID} trusts the connector's AWS role`
        ),
        data: { type: "insufficient_privileges" },
      });
    });
  });

  describe("requireAccountAdmin", () => {
    it("finds the service principal in account SCIM and checks its roles", async () => {
      const fetchMock = stubFetch(databricks(account));

      await expect(
        validate({ ...accountContext(), requireAccountAdmin: true })
      ).resolves.toMatchObject({ servicePrincipal });

      expect(databricksCalls(fetchMock).map(({ url }) => url)).toEqual([
        `${ACCOUNT_API}/scim/v2/ServicePrincipals?${new URLSearchParams({
          filter: `applicationId eq "${APPLICATION_ID}"`,
        }).toString()}`,
        `${ACCOUNT_API}/scim/v2/ServicePrincipals/${SP_SCIM_ID}`,
      ]);
    });

    it("refuses a principal without account_admin", async () => {
      account.servicePrincipals = [{ ...OWN_PRINCIPAL, roles: [] }];
      stubFetch(databricks(account));

      await expect(
        validate({ ...accountContext(), requireAccountAdmin: true })
      ).rejects.toMatchObject(notAccountAdmin);
    });

    it.each([
      ["the lookup", "GET /scim/v2/ServicePrincipals"],
      ["the fresh read", `GET /scim/v2/ServicePrincipals/${SP_SCIM_ID}`],
    ])(
      "gives the same refusal when account SCIM answers %s with a 403",
      async (_, call) => {
        account.refuse[call] = 403;
        stubFetch(databricks(account));

        await expect(
          validate({ ...accountContext(), requireAccountAdmin: true })
        ).rejects.toMatchObject(notAccountAdmin);
      }
    );
  });

  describe("requireMetastoreAdmin", () => {
    const check = () =>
      validate({ ...accountContext(), requireMetastoreAdmin: true });

    const ownedBy = (owner?: string, name = "main-us-east-1") => ({
      metastore_id: METASTORE_ID,
      name,
      ...(owner !== undefined ? { owner } : {}),
    });

    it("passes a metastore P0's principal owns by application ID", async () => {
      account.metastores = [ownedBy(APPLICATION_ID)];
      const fetchMock = stubFetch(databricks(account));

      await expect(check()).resolves.toMatchObject({
        metastores: [
          {
            metastoreId: METASTORE_ID,
            name: "main-us-east-1",
            owner: APPLICATION_ID,
          },
        ],
      });
      expect(databricksCalls(fetchMock).map(({ url }) => url)).toContain(
        `${ACCOUNT_API}/metastores`
      );
    });

    it("passes a metastore owned by a group P0's principal is a direct member of", async () => {
      account.metastores = [ownedBy("metastore-admins")];
      account.groups = [
        {
          id: "3001",
          displayName: "metastore-admins",
          members: ["1001", SP_SCIM_ID],
        },
      ];
      const fetchMock = stubFetch(databricks(account));

      await expect(check()).resolves.toMatchObject({
        metastores: [{ owner: "metastore-admins" }],
      });
      expect(databricksCalls(fetchMock).map(({ url }) => url)).toContain(
        `${ACCOUNT_API}/scim/v2/Groups/3001`
      );
    });

    it("passes an account with no metastore", async () => {
      stubFetch(databricks(account));

      await expect(check()).resolves.toMatchObject({ metastores: [] });
    });

    it("refuses a metastore with no owner, naming it", async () => {
      account.metastores = [ownedBy()];
      stubFetch(databricks(account));

      await expect(check()).rejects.toMatchObject({
        message: `Databricks metastore main-us-east-1 (${METASTORE_ID}) has no owner. ${metastoreRemedy}`,
        data: {
          type: "insufficient_privileges",
          payload: { metastoreId: METASTORE_ID },
        },
      });
    });

    it("refuses a metastore owned by a group P0's principal isn't a direct member of", async () => {
      account.metastores = [ownedBy("metastore-admins")];
      account.groups = [
        { id: "3001", displayName: "metastore-admins", members: ["3002"] },
        // P0 is only in a group nested in the owner group, which doesn't count.
        { id: "3002", displayName: "nested", members: [SP_SCIM_ID] },
      ];
      stubFetch(databricks(account));

      await expect(check()).rejects.toMatchObject({
        message: `Databricks metastore main-us-east-1 (${METASTORE_ID}) is owned by group metastore-admins, which service principal ${APPLICATION_ID} is not a direct member of. Add group metastore-admins to the account Terraform's metastore admin groups, then apply it.`,
        data: { type: "insufficient_privileges" },
      });
    });

    it("refuses a metastore owned by anyone else", async () => {
      account.metastores = [ownedBy("alice@example.com")];
      stubFetch(databricks(account));

      await expect(check()).rejects.toMatchObject({
        message: `Databricks metastore main-us-east-1 (${METASTORE_ID}) is owned by alice@example.com, which is neither service principal ${APPLICATION_ID} nor a group. ${metastoreRemedy}`,
        data: { type: "insufficient_privileges" },
      });
    });

    it("checks every metastore, and names the one that fails", async () => {
      account.metastores = [
        ownedBy(APPLICATION_ID, "main-us-east-1"),
        {
          ...ownedBy("alice@example.com", "main-eu-west-1"),
          metastore_id: "22222222-aaaa-4bbb-8ccc-333333333333",
        },
      ];
      stubFetch(databricks(account));

      await expect(check()).rejects.toMatchObject({
        message: expect.stringMatching(
          /^Databricks metastore main-eu-west-1 \(22222222-aaaa-4bbb-8ccc-333333333333\) is owned by alice@example.com/
        ),
      });
    });

    it("says P0's principal isn't an account admin when the metastore list answers 403", async () => {
      account.refuse["GET /metastores"] = 403;
      stubFetch(databricks(account));

      await expect(check()).rejects.toMatchObject(notAccountAdmin);
    });
  });

  describe("ownerPrincipal", () => {
    const check = (ownerPrincipal: string) =>
      validate({ ...accountContext(), ownerPrincipal });

    const OTHER_APP_ID = "11111111-2222-4333-8444-555555555555";

    it.each([
      [
        "a group by display name",
        (a: FakeAccount) => {
          a.groups = [{ id: "3001", displayName: "data-owners", members: [] }];
        },
        "data-owners",
        { type: "group", id: "3001", name: "data-owners" },
      ],
      [
        "a user by userName",
        (a: FakeAccount) => {
          a.users = [{ id: "1001", userName: "alice@example.com" }];
        },
        "alice@example.com",
        { type: "user", id: "1001", name: "alice@example.com" },
      ],
      [
        "a service principal by application ID",
        (a: FakeAccount) => {
          a.servicePrincipals = [
            OWN_PRINCIPAL,
            { id: "2001", applicationId: OTHER_APP_ID },
          ];
        },
        OTHER_APP_ID,
        { type: "servicePrincipal", id: "2001", name: OTHER_APP_ID },
      ],
    ])("finds %s", async (_, setUp, ownerPrincipal, expected) => {
      setUp(account);
      stubFetch(databricks(account));

      await expect(check(ownerPrincipal)).resolves.toMatchObject({
        ownerPrincipal: expected,
      });
    });

    it("refuses a name no principal has", async () => {
      stubFetch(databricks(account));

      await expect(check("nobody")).rejects.toMatchObject({
        message: `No group, user or service principal in Databricks account ${ACCOUNT_ID} is named nobody. Set the owner principal to a group's display name, a user's userName, or a service principal's application ID.`,
        data: { type: "object_not_found" },
      });
    });

    it("refuses a name more than one principal has, naming each", async () => {
      account.groups = [
        { id: "3001", displayName: "alice@example.com", members: [] },
      ];
      account.users = [{ id: "1001", userName: "alice@example.com" }];
      stubFetch(databricks(account));

      await expect(check("alice@example.com")).rejects.toMatchObject({
        message: `The owner principal alice@example.com names more than one principal in Databricks account ${ACCOUNT_ID}: group 3001, user 1001. Set it to one that names a single group, user or service principal.`,
        data: { type: "validation_error" },
      });
    });
  });

  it("runs every check without writing anything", async () => {
    account.metastores = [
      { metastore_id: METASTORE_ID, name: "main", owner: APPLICATION_ID },
    ];
    account.users = [{ id: "1001", userName: "alice@example.com" }];
    const fetchMock = stubFetch(databricks(account));

    await expect(
      validate({
        ...accountContext(),
        requireAccountAdmin: true,
        requireMetastoreAdmin: true,
        ownerPrincipal: "alice@example.com",
      })
    ).resolves.toEqual({
      servicePrincipal,
      metastores: [
        { metastoreId: METASTORE_ID, name: "main", owner: APPLICATION_ID },
      ],
      ownerPrincipal: { type: "user", id: "1001", name: "alice@example.com" },
    });

    const calls = databricksCalls(fetchMock);
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every(({ init }) => init.method === "GET")).toBe(true);
  });

  describe("input", () => {
    it.each<[string, InstallValidationInput]>([
      [
        "an account ID that isn't a GUID",
        accountContext({ accountId: "../x" }),
      ],
      [
        "the AWS GovCloud account console",
        accountContext({ accountsUrl: "https://accounts.cloud.databricks.us" }),
      ],
      [
        "the Azure account console",
        accountContext({ accountsUrl: "https://accounts.azuredatabricks.net" }),
      ],
      [
        "the GCP account console",
        accountContext({ accountsUrl: "https://accounts.gcp.databricks.com" }),
      ],
      ["an empty owner principal", { ...accountContext(), ownerPrincipal: "" }],
    ])("refuses %s before calling anything", async (_, input) => {
      const fetchMock = stubFetch(databricks(account));

      await expect(validate(input)).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("rejects a field it doesn't know instead of validating less", async () => {
      const fetchMock = stubFetch(databricks(account));

      await expect(
        validate({
          ...accountContext(),
          // @ts-expect-error a misspelled field, which the strict schema must refuse
          requireAccountAdmn: true,
        })
      ).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });
});

describe("install validation probe", () => {
  const assignmentsPath = `${ACCOUNT_API}/workspaces/${WORKSPACE_ID}/permissionassignments`;
  const mcpUrl = `${WORKSPACE_URL}${DBSQL_MCP_PATH}`;

  it("looks the workspace up, makes P0 its admin, then lists the Databricks SQL MCP server's tools", async () => {
    const fetchMock = stubFetch(databricks(account));

    await expect(probe()).resolves.toEqual({
      workspaceId: WORKSPACE_ID,
      workspaceName: "analytics",
      workspaceHost: WORKSPACE_URL,
      unityGatewayBeta: true,
    });

    const calls = databricksCalls(fetchMock);
    expect(calls.map(({ url, init }) => `${init.method} ${url}`)).toEqual([
      `GET ${ACCOUNT_API}/workspaces/${WORKSPACE_ID}`,
      `GET ${ACCOUNT_API}/scim/v2/ServicePrincipals?${new URLSearchParams({
        filter: `applicationId eq "${APPLICATION_ID}"`,
      }).toString()}`,
      `GET ${assignmentsPath}`,
      `PUT ${assignmentsPath}/principals/${SP_SCIM_ID}`,
      `POST ${mcpUrl}`,
      `POST ${mcpUrl}`,
      `POST ${mcpUrl}`,
    ]);
    expect(JSON.parse(calls[3]?.init.body ?? "")).toEqual({
      permissions: ["ADMIN"],
    });
  });

  it("starts an MCP session the way the streamable HTTP transport requires", async () => {
    const fetchMock = stubFetch(databricks(account));

    await probe();

    const mcp = databricksCalls(fetchMock).filter(({ url }) => url === mcpUrl);
    expect(mcp.map(({ init }) => JSON.parse(init.body ?? ""))).toEqual([
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "p0-connector-databricks-ai", version: "1.0.0" },
        },
      },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
    ]);
    for (const { init } of mcp) {
      expect(init.headers).toMatchObject({
        Accept: MCP_ACCEPT,
        "Content-Type": "application/json",
      });
    }
    expect(MCP_ACCEPT).toBe("application/json, text/event-stream");
    expect(account.mcpCalls.map(({ sessionId }) => sessionId)).toEqual([
      undefined,
      "session-1",
      "session-1",
    ]);
  });

  it("sends no session ID when the server names none", async () => {
    account.mcp = [{ status: 200 }];
    stubFetch(databricks(account));

    await expect(probe()).resolves.toMatchObject({ unityGatewayBeta: true });
    expect(account.mcpCalls.map(({ sessionId }) => sessionId)).toEqual([
      undefined,
      undefined,
      undefined,
    ]);
  });

  it("reads only each answer's status, never a body that may be an open event stream", async () => {
    account.mcp = [{ status: 200, endlessBody: true }];
    stubFetch(databricks(account));

    await expect(probe()).resolves.toMatchObject({ unityGatewayBeta: true });
  });

  it.each([
    ["by account SCIM ID", { principal_id: Number(SP_SCIM_ID) }],
    [
      "by application ID, when the ID didn't survive JSON parsing",
      { principal_id: 2 ** 53 + 2, service_principal_name: APPLICATION_ID },
    ],
  ])(
    "writes nothing when P0 is already an admin, matched %s",
    async (_, principal) => {
      account.assignments = [{ principal, permissions: ["ADMIN"] }];
      const fetchMock = stubFetch(databricks(account));

      await expect(probe()).resolves.toMatchObject({ unityGatewayBeta: true });
      expect(
        databricksCalls(fetchMock).some(({ init }) => init.method === "PUT")
      ).toBe(false);
    }
  );

  it("raises P0 from USER to ADMIN", async () => {
    account.assignments = [
      {
        principal: { principal_id: Number(SP_SCIM_ID) },
        permissions: ["USER"],
      },
      // Another principal's ADMIN doesn't count.
      { principal: { user_name: "alice@example.com" }, permissions: ["ADMIN"] },
    ];
    const fetchMock = stubFetch(databricks(account));

    await probe();

    expect(
      databricksCalls(fetchMock)
        .filter(({ init }) => init.method === "PUT")
        .map(({ url, init }) => [url, init.body])
    ).toEqual([
      [
        `${assignmentsPath}/principals/${SP_SCIM_ID}`,
        JSON.stringify({ permissions: ["ADMIN"] }),
      ],
    ]);
  });

  it("reports the beta off when tools/list answers 404", async () => {
    account.assignments = [
      {
        principal: { principal_id: Number(SP_SCIM_ID) },
        permissions: ["ADMIN"],
      },
    ];
    account.mcp = [{ status: 200 }, { status: 202 }, { status: 404 }];
    stubFetch(databricks(account));

    await expect(probe()).resolves.toMatchObject({ unityGatewayBeta: false });
  });

  it.each([401, 403])(
    "fails with what to check when tools/list answers %i and P0 was already admin",
    async (status) => {
      account.assignments = [
        {
          principal: { principal_id: Number(SP_SCIM_ID) },
          permissions: ["ADMIN"],
        },
      ];
      account.mcp = [{ status: 200 }, { status: 202 }, { status }];
      stubFetch(databricks(account));

      await expect(probe()).rejects.toMatchObject({
        message: `Databricks Unity Gateway refused P0's service principal on the Databricks SQL MCP server in workspace ${WORKSPACE_ID} (MCP tools/list answered ${status}). Callers invoke the system.ai MCP servers through the EXECUTE privilege that account users hold on the system.ai schema by default. Make sure account users still hold it, then try again.`,
        data: { type: "insufficient_privileges" },
      });
    }
  );

  it.each([401, 403])(
    "fails instead of reporting the beta off when tools/list answers %i right after P0 became admin",
    async (status) => {
      account.mcp = [{ status: 200 }, { status: 202 }, { status }];
      stubFetch(databricks(account));

      await expect(probe()).rejects.toMatchObject({
        message: `Databricks hasn't seen P0's new workspace admin assignment in workspace ${WORKSPACE_ID} yet. Try again in a few minutes.`,
        data: { type: "upstream_unavailable" },
      });
    }
  );

  it("reports the beta off, and stops, when initialize answers 404", async () => {
    account.mcp = [{ status: 404 }, { status: 200 }];
    stubFetch(databricks(account));

    await expect(probe()).resolves.toMatchObject({ unityGatewayBeta: false });
    expect(account.mcpCalls.map(({ method }) => method)).toEqual([
      "initialize",
    ]);
  });

  it.each([
    [500, "upstream_unavailable"],
    [503, "upstream_unavailable"],
    [429, "rate_limited"],
    [400, "unknown"],
    [406, "unknown"],
  ])(
    "fails instead of guessing when the gateway answers %i",
    async (status, type) => {
      account.mcp = [{ status: 200 }, { status: 202 }, { status }];
      stubFetch(databricks(account));

      await expect(probe()).rejects.toMatchObject({
        message: `Databricks Unity Gateway answered MCP tools/list with ${status}, so P0 can't tell whether the Unity Gateway beta is on. Try again in a few minutes.`,
        data: { type },
      });
    }
  );

  it("builds the AWS workspace host from its deployment name", async () => {
    account.workspaces = [
      { ...account.workspaces[0], deployment_name: DEPLOYMENT_NAME },
    ];
    const fetchMock = stubFetch(databricks(account));

    await expect(probe()).resolves.toMatchObject({
      workspaceHost: WORKSPACE_URL,
    });
    expect(
      databricksCalls(fetchMock)
        .filter(({ init }) => init.method === "POST")
        .map(({ url }) => url)
    ).toEqual([
      `${WORKSPACE_URL}${DBSQL_MCP_PATH}`,
      `${WORKSPACE_URL}${DBSQL_MCP_PATH}`,
      `${WORKSPACE_URL}${DBSQL_MCP_PATH}`,
    ]);
  });

  it.each([
    ["no deployment name", undefined],
    ["a deployment name that leaves the Databricks domain", "evil.example/x#"],
    ["a deployment name with a port", "dbc-1:8443"],
  ])(
    "refuses a workspace with %s, sending nothing to its host",
    async (_, deploymentName) => {
      account.workspaces = [
        { ...account.workspaces[0], deployment_name: deploymentName },
      ];
      const fetchMock = stubFetch(databricks(account));

      await expect(probe()).rejects.toMatchObject({
        message: `P0 can't build a Databricks workspace URL for workspace ${WORKSPACE_ID} from its deployment name.`,
        data: { type: "validation_error" },
      });
      expect(
        databricksCalls(fetchMock).every(({ url }) =>
          url.startsWith(ACCOUNT_API)
        )
      ).toBe(true);
    }
  );

  it("refuses a workspace that isn't running", async () => {
    account.workspaces = [
      { ...account.workspaces[0], workspace_status: "PROVISIONING" },
    ];
    stubFetch(databricks(account));

    await expect(probe()).rejects.toMatchObject({
      message: `Databricks workspace ${WORKSPACE_ID} is PROVISIONING, not RUNNING. Wait until it is running, then try again.`,
      data: { type: "validation_error" },
    });
  });

  it("says the account has no such workspace", async () => {
    account.workspaces = [];
    stubFetch(databricks(account));

    await expect(probe()).rejects.toMatchObject({
      message: `Databricks account ${ACCOUNT_ID} has no workspace ${WORKSPACE_ID}. Check the workspace ID.`,
      data: { type: "object_not_found" },
    });
  });

  it.each([
    `GET /workspaces/${WORKSPACE_ID}`,
    `GET /workspaces/${WORKSPACE_ID}/permissionassignments`,
    `PUT /workspaces/${WORKSPACE_ID}/permissionassignments/principals/${SP_SCIM_ID}`,
  ])(
    "says P0's principal isn't an account admin when %s answers 403",
    async (call) => {
      account.refuse[call] = 403;
      stubFetch(databricks(account));

      await expect(probe()).rejects.toMatchObject(notAccountAdmin);
      expect(account.mcpCalls).toEqual([]);
    }
  );

  it("refuses a workspace ID that isn't digits before calling anything", async () => {
    const fetchMock = stubFetch(databricks(account));

    await expect(probe({ workspaceId: "../1" })).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
