import { createLogger } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeAccount,
  OWN_PRINCIPAL,
  databricks,
  fakeAccount,
  workspaceScimId,
} from "../../__tests__/databricks.ts";
import {
  ACCOUNT_ID,
  SP_SCIM_ID,
  WORKSPACE_ID,
  WORKSPACE_URL,
  accountContext,
  databricksCalls,
  jsonResponse,
  resetBetweenTests,
  stubFetch,
} from "../../__tests__/http.ts";
import { newDatabricksClient } from "../../databricks/client.ts";
import {
  AGENT_ENTITLEMENTS,
  FEDERATION_POLICY_ID,
  createUser,
  deleteUser,
  federationPolicyBody,
  getUser,
} from "../agent.ts";
import type { AgentContext } from "../context.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);

const { mockedSleep } = vi.hoisted(() => ({
  mockedSleep: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("node:timers/promises", () => ({ setTimeout: mockedSleep }));

resetBetweenTests();

const NAME = "p0-agent-req_123";
const AGENT_ID = "8100000000000001";
const AGENT_APPLICATION_ID = "3a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const ISSUER = "https://p0.example.com/oauth";
const SUBJECT = "mcps/databricksSql/abc123";

const context = (overrides: Partial<AgentContext> = {}): AgentContext => ({
  ...accountContext(),
  workspaceId: WORKSPACE_ID,
  agentApplicationId: AGENT_APPLICATION_ID,
  federation: { issuer: ISSUER, subject: SUBJECT },
  ...overrides,
});

/** The principal `principal.stage` created: active, and holding nothing. */
const stagedPrincipal = () => ({
  id: AGENT_ID,
  applicationId: AGENT_APPLICATION_ID,
  displayName: NAME,
  active: true,
});

let account: FakeAccount;

beforeEach(() => {
  account = fakeAccount();
  account.servicePrincipals.push(stagedPrincipal());
  mockedSleep.mockClear();
});

const logger = createLogger();
const client = (overrides: Partial<AgentContext> = {}) =>
  newDatabricksClient(context(overrides));
const get = (overrides: Partial<AgentContext> = {}) =>
  getUser(client(overrides), logger, context(overrides), NAME);
const create = (overrides: Partial<AgentContext> = {}) =>
  createUser(client(overrides), logger, context(overrides), NAME);
const remove = () => deleteUser(client(), logger, context(), NAME);

const ACCOUNT_PATH = `/api/2.0/accounts/${ACCOUNT_ID}`;
const ASSIGNMENT = `${ACCOUNT_PATH}/workspaces/${WORKSPACE_ID}/permissionassignments/principals/${AGENT_ID}`;
const POLICIES = `${ACCOUNT_PATH}/servicePrincipals/${AGENT_ID}/federationPolicies`;
const WORKSPACE_PRINCIPALS = "/api/2.0/preview/scim/v2/ServicePrincipals";
const WORKSPACE_PRINCIPAL = `${WORKSPACE_PRINCIPALS}/${workspaceScimId(AGENT_ID)}`;

const agentAssignment = () =>
  account.assignments.find(
    (a) => String(a.principal.principal_id) === AGENT_ID
  );

/** What a finished grant setup leaves in the account. */
const expectFinished = () => {
  expect(agentAssignment()?.permissions).toEqual(["USER"]);
  expect(account.entitlements[AGENT_ID]).toEqual([...AGENT_ENTITLEMENTS]);
  expect(account.policies[AGENT_ID]).toEqual([
    {
      policy_id: FEDERATION_POLICY_ID,
      oidc_policy: federationPolicyBody(context()).oidc_policy,
    },
  ]);
};

/** What an undone or cleaned-up grant leaves: the bare principal. */
const expectBare = () => {
  expect(account.servicePrincipals.map(({ id }) => id)).toContain(AGENT_ID);
  expect(agentAssignment()).toBeUndefined();
  expect(account.entitlements[AGENT_ID] ?? []).toEqual([]);
  expect(account.policies[AGENT_ID] ?? []).toEqual([]);
};

describe("federationPolicyBody", () => {
  it("trusts P0's auth server for the session's subject, with the account as audience", () => {
    expect(federationPolicyBody(context())).toEqual({
      oidc_policy: {
        issuer: ISSUER,
        audiences: [ACCOUNT_ID],
        subject: SUBJECT,
      },
    });
  });
});

describe("createUser", () => {
  it("assigns the principal, adds and reads back its entitlements, and creates its policy last", async () => {
    const fetchMock = stubFetch(databricks(account));

    await expect(create()).resolves.toBe(NAME);

    expectFinished();
    // P0 became workspace admin on the way, and stays one.
    expect(
      account.assignments.find(
        (a) => String(a.principal.principal_id) === SP_SCIM_ID
      )?.permissions
    ).toEqual(["ADMIN"]);
    const writes = databricksCalls(fetchMock)
      .filter(({ init }) => init.method !== "GET")
      .map(({ url, init }) => `${init.method} ${new URL(url).pathname}`);
    expect(writes).toEqual([
      `PUT ${ACCOUNT_PATH}/workspaces/${WORKSPACE_ID}/permissionassignments/principals/${SP_SCIM_ID}`,
      `PUT ${ASSIGNMENT}`,
      `PATCH ${WORKSPACE_PRINCIPAL}`,
      `PATCH ${WORKSPACE_PRINCIPAL}`,
      `POST ${POLICIES}`,
    ]);
    const post = databricksCalls(fetchMock).find(
      ({ init }) => init.method === "POST"
    );
    expect(new URL(post?.url ?? "").searchParams.get("policy_id")).toBe(
      FEDERATION_POLICY_ID
    );
    // Entitlements go to the workspace's own SCIM ID, on the workspace host.
    expect(
      databricksCalls(fetchMock)
        .filter(({ init }) => init.method === "PATCH")
        .map(({ url, init }) => [
          new URL(url).origin,
          JSON.parse(init.body ?? ""),
        ])
    ).toEqual(
      AGENT_ENTITLEMENTS.map((value) => [
        WORKSPACE_URL,
        {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ op: "add", path: "entitlements", value: [{ value }] }],
        },
      ])
    );
  });

  it("is found by getUser once it finished, so a repeated grant changes nothing", async () => {
    stubFetch(databricks(account));
    await expect(get()).resolves.toBeNull();
    await expect(create()).resolves.toBe(NAME);

    const fetchMock = stubFetch(databricks(account));
    await expect(get()).resolves.toBe(NAME);

    expect(
      databricksCalls(fetchMock).every(({ init }) => init.method === "GET")
    ).toBe(true);
    expectFinished();
  });

  it("finishes on a retry after a create that failed halfway", async () => {
    stubFetch(databricks(account));
    account.fail[`PATCH ${WORKSPACE_PRINCIPAL}`] = 503;
    await expect(create()).rejects.toMatchObject({
      data: { type: "upstream_unavailable" },
    });

    delete account.fail[`PATCH ${WORKSPACE_PRINCIPAL}`];
    await expect(get()).resolves.toBeNull();
    await expect(create()).resolves.toBe(NAME);

    expectFinished();
  });

  it.each([
    ["the workspace assignment", `PUT ${ASSIGNMENT}`],
    ["the workspace SCIM lookup", `GET ${WORKSPACE_PRINCIPALS}`],
    ["an entitlement", `PATCH ${WORKSPACE_PRINCIPAL}`],
    ["the read-back", `GET ${WORKSPACE_PRINCIPAL}`],
    ["the federation policy", `POST ${POLICIES}`],
  ])(
    "undoes what ran when %s fails, leaving the bare principal",
    async (_, call) => {
      stubFetch(databricks(account));
      account.fail[call] = 500;

      await expect(create()).rejects.toMatchObject({
        data: { type: "upstream_unavailable" },
      });

      expectBare();
    }
  );

  it("fails, and undoes, when the workspace drops an entitlement", async () => {
    const fetchMock = stubFetch((url, init) => {
      // The read-back sees only the first entitlement.
      if (
        init.method === "GET" &&
        new URL(url).pathname === WORKSPACE_PRINCIPAL
      ) {
        account.entitlements[AGENT_ID] = [AGENT_ENTITLEMENTS[0]];
      }
      return databricks(account)(url, init);
    });

    await expect(create()).rejects.toMatchObject({
      message: `Databricks workspace ${WORKSPACE_ID} didn't keep entitlements databricks-sql-access for service principal ${AGENT_APPLICATION_ID}`,
    });

    expectBare();
    expect(
      databricksCalls(fetchMock).some(({ init }) => init.method === "POST")
    ).toBe(false);
  });

  it("keeps unwinding when an undo fails, and throws the step's error", async () => {
    account.fail[`POST ${POLICIES}`] = 500;
    // The entitlement adds succeed. Their undos, which run after the policy
    // fails, don't.
    const fetchMock = stubFetch((url, init) => {
      if (init.method === "POST") {
        account.fail[`PATCH ${WORKSPACE_PRINCIPAL}`] = 500;
      }
      return databricks(account)(url, init);
    });

    await expect(create()).rejects.toMatchObject({
      message: expect.stringContaining(`POST ${POLICIES} failed (500)`),
    });

    // Both entitlement removals were tried, and the unassignment still ran.
    expect(agentAssignment()).toBeUndefined();
    expect(
      databricksCalls(fetchMock).filter(({ init }) => init.method === "PATCH")
    ).toHaveLength(4);
  });

  it("says to retry when the workspace hasn't seen the new assignment yet", async () => {
    stubFetch(databricks(account));
    account.fail[`GET ${WORKSPACE_PRINCIPALS}`] = 403;

    await expect(create()).rejects.toMatchObject({
      message: `Databricks workspace ${WORKSPACE_ID} refused P0's service principal (403). A new workspace assignment can take a few minutes to reach a workspace. Try again shortly.`,
      data: { type: "upstream_unavailable" },
    });
    expectBare();
  });

  it("waits for the workspace to list the new principal, then finishes", async () => {
    let lookups = 0;
    // The workspace lists the principal only from its second lookup on.
    stubFetch((url, init) => {
      if (
        init.method === "GET" &&
        new URL(url).pathname === WORKSPACE_PRINCIPALS &&
        ++lookups === 1
      ) {
        return jsonResponse({ Resources: [] });
      }
      return databricks(account)(url, init);
    });

    await expect(create()).resolves.toBe(NAME);

    expect(lookups).toBe(2);
    expect(mockedSleep).toHaveBeenCalledTimes(1);
    expectFinished();
  });

  it("fails, and undoes, when the workspace never lists the new principal", async () => {
    stubFetch((url, init) =>
      init.method === "GET" && new URL(url).pathname === WORKSPACE_PRINCIPALS
        ? jsonResponse({ Resources: [] })
        : databricks(account)(url, init)
    );

    await expect(create()).rejects.toMatchObject({
      message: `Databricks workspace ${WORKSPACE_ID} doesn't list service principal ${AGENT_APPLICATION_ID} yet. Try again shortly.`,
      data: { type: "upstream_unavailable" },
    });

    // About 60 s in all, well inside the 270 s Lambda.
    const waited = mockedSleep.mock.calls.reduce(
      (total, [delay]) => total + Number(delay),
      0
    );
    expect(waited).toBe(60_000);
    expectBare();
  });

  it("refuses a principal stage didn't create, and creates nothing", async () => {
    account.servicePrincipals = [OWN_PRINCIPAL];
    const fetchMock = stubFetch(databricks(account));

    await expect(create()).rejects.toMatchObject({
      message: `No Databricks service principal is named ${NAME}. P0 grants only to the service principal it created when the request was staged. Make the request again.`,
      data: { type: "validation_error" },
    });
    expect(
      databricksCalls(fetchMock).every(({ init }) => init.method === "GET")
    ).toBe(true);
  });

  it("refuses a principal with another application ID", async () => {
    const other = "11111111-2222-4333-8444-555555555555";
    account.servicePrincipals[1] = {
      ...stagedPrincipal(),
      applicationId: other,
    };
    stubFetch(databricks(account));

    await expect(create()).rejects.toMatchObject({
      message: `Databricks service principal ${NAME} has application ID ${other}, not ${AGENT_APPLICATION_ID}. P0 grants only to the service principal it created when the request was staged. Make the request again.`,
    });
    await expect(get()).rejects.toMatchObject({
      data: { type: "validation_error" },
    });
  });
});

describe("getUser", () => {
  it("returns null for no principal", async () => {
    account.servicePrincipals = [OWN_PRINCIPAL];
    stubFetch(databricks(account));

    await expect(get()).resolves.toBeNull();
  });

  it("returns null for the bare principal stage created, without a warning or a write", async () => {
    const warn = vi.spyOn(logger, "warn");
    const fetchMock = stubFetch(databricks(account));

    await expect(get()).resolves.toBeNull();

    expect(warn).not.toHaveBeenCalled();
    expect(
      databricksCalls(fetchMock).every(({ init }) => init.method === "GET")
    ).toBe(true);
    warn.mockRestore();
  });

  it("removes an unfinished principal's policies and assignment, and returns null", async () => {
    account.assignments.push({
      principal: { principal_id: Number(AGENT_ID) },
      permissions: ["USER"],
    });
    account.entitlements[AGENT_ID] = [AGENT_ENTITLEMENTS[0]];
    account.policies[AGENT_ID] = [{ policy_id: "stray", oidc_policy: {} }];
    stubFetch(databricks(account));

    await expect(get()).resolves.toBeNull();

    expectBare();
  });

  it("returns an inactive principal even without its policy, so a failed revoke is retried", async () => {
    account.servicePrincipals[1] = { ...stagedPrincipal(), active: false };
    const fetchMock = stubFetch(databricks(account));

    await expect(get()).resolves.toBe(NAME);
    expect(
      databricksCalls(fetchMock).every(({ init }) => init.method === "GET")
    ).toBe(true);
  });

  it("matches the display name exactly, not case-insensitively", async () => {
    account.servicePrincipals[1] = {
      ...stagedPrincipal(),
      displayName: NAME.toUpperCase().replace("P0-AGENT-", "p0-agent-"),
    };
    stubFetch(databricks(account));

    await expect(get()).resolves.toBeNull();
  });

  it("refuses two principals with the name, naming both", async () => {
    account.servicePrincipals.push({
      ...stagedPrincipal(),
      id: "8100000000000002",
    });
    stubFetch(databricks(account));

    await expect(get()).rejects.toMatchObject({
      message: expect.stringContaining(`${AGENT_ID}, 8100000000000002`),
    });
  });

  it("refuses P0's own principal", async () => {
    account.servicePrincipals = [{ ...OWN_PRINCIPAL, displayName: NAME }];
    stubFetch(databricks(account));

    await expect(
      get({ agentApplicationId: OWN_PRINCIPAL.applicationId })
    ).rejects.toMatchObject({
      message:
        "P0 cannot grant access to its own Databricks service principal.",
    });
  });
});

describe("deleteUser", () => {
  it("deletes the policy, then the principal", async () => {
    stubFetch(databricks(account));
    await create();
    const fetchMock = stubFetch(databricks(account));

    await remove();

    expect(account.servicePrincipals.map(({ id }) => id)).not.toContain(
      AGENT_ID
    );
    expect(
      databricksCalls(fetchMock)
        .filter(({ init }) => init.method === "DELETE")
        .map(({ url }) => new URL(url).pathname)
    ).toEqual([
      `${POLICIES}/${FEDERATION_POLICY_ID}`,
      `${ACCOUNT_PATH}/scim/v2/ServicePrincipals/${AGENT_ID}`,
    ]);
  });

  it("is done when the principal is already gone", async () => {
    account.servicePrincipals = [OWN_PRINCIPAL];
    const fetchMock = stubFetch(databricks(account));

    await expect(remove()).resolves.toBeUndefined();
    expect(
      databricksCalls(fetchMock).some(({ init }) => init.method === "DELETE")
    ).toBe(false);
  });

  it("counts a policy or principal already gone as done", async () => {
    account.policies[AGENT_ID] = [
      { policy_id: FEDERATION_POLICY_ID, oidc_policy: {} },
    ];
    account.fail[`DELETE ${POLICIES}/${FEDERATION_POLICY_ID}`] = {
      status: 404,
      errorCode: "RESOURCE_DOES_NOT_EXIST",
    };
    account.fail[
      `DELETE ${ACCOUNT_PATH}/scim/v2/ServicePrincipals/${AGENT_ID}`
    ] = { status: 404, errorCode: "RESOURCE_DOES_NOT_EXIST" };
    stubFetch(databricks(account));

    await expect(remove()).resolves.toBeUndefined();
  });

  it("leaves the principal when a policy delete fails, so the retry finds it", async () => {
    stubFetch(databricks(account));
    await create();
    account.fail[`DELETE ${POLICIES}/${FEDERATION_POLICY_ID}`] = 500;

    await expect(remove()).rejects.toMatchObject({
      data: { type: "upstream_unavailable" },
    });

    expect(account.servicePrincipals.map(({ id }) => id)).toContain(AGENT_ID);
    delete account.fail[`DELETE ${POLICIES}/${FEDERATION_POLICY_ID}`];
    await expect(get()).resolves.toBe(NAME);
    await remove();
    expect(account.servicePrincipals.map(({ id }) => id)).not.toContain(
      AGENT_ID
    );
  });
});
