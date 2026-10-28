import { createLogger } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  ACCOUNTS_URL,
  ACCOUNT_ID,
  APPLICATION_ID,
  METASTORE_ASSIGNMENT,
  SP_SCIM_ID,
  WORKSPACE_ID,
  WORKSPACE_URL,
  accountContext,
  bindingResponse,
  fetchCalls,
  isBinding,
  isTokenExchange,
  jsonResponse,
  resetBetweenTests,
  stubFetch,
} from "../../../__tests__/http.ts";
import { domainWarnings, warn } from "../../../__tests__/logs.ts";
import { WORKSPACE_PAIR_ERROR } from "../../../databricks/workspaces.ts";
import { DOMAIN_PATTERN_ENV } from "../../../domain.ts";
import { connectorRouter } from "../../../router.ts";
import { type schema, spec } from "../definition.ts";
import { adminScopeOf } from "../handler.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);
vi.mock("@p0security/connector", async (importOriginal) =>
  (await import("../../../__tests__/logs.ts")).recordingLoggerModule(
    importOriginal
  )
);

resetBetweenTests();

type RequestContext = z.input<typeof schema.requestContext>;
type Policy = z.input<typeof schema.policy>;
type ListerQuery = z.input<typeof schema.listerQuery>;
type UserBody = z.input<typeof schema.userBody>;

const ALICE_ID = "1111111111111111";
const ALICE = "alice@example.com";
const GROUP_ID = "3333333333333333";

/** The workspace's proxy of account SCIM `Users`. */
const PROXY_USERS = "/api/2.0/account/scim/v2/Users";
/** The workspace's own permission assignment API. */
const ASSIGNMENTS = "/api/2.0/preview/permissionassignments";

type FakeUser = {
  id: string;
  userName: string;
  emails?: { value: string }[];
  roles?: { value: string }[];
};

/** The SCIM `PATCH` body the connector sends, as Databricks would accept it. */
const scimPatch = z.object({
  Operations: z.array(
    z.object({
      op: z.enum(["add", "remove"]),
      path: z.string().optional(),
      value: z
        .object({ roles: z.array(z.object({ value: z.string() })) })
        .optional(),
    })
  ),
});

/** The workspace assignment `PUT` body the connector sends. */
const assignmentPut = z.object({ permissions: z.array(z.string()) });

const forbidden = () =>
  jsonResponse(
    { error_code: "PERMISSION_DENIED", message: "not an admin" },
    { status: 403 }
  );

/**
 * An in-memory Databricks account and one of its workspaces. The account
 * console serves account SCIM users and the connector's service principal.
 * The workspace, at `WORKSPACE_URL`, serves its metastore assignment, which
 * binding reads, its `SCIM /Me`, its proxy of account SCIM `Users`, and its
 * permission assignments. Neither serves anything else, so a call sent to the
 * wrong host fails.
 *
 * `ignoreWrites` makes every write succeed without changing anything, as an
 * eventually consistent or misbehaving API would. Turning `workspaceUp` off
 * makes the workspace's URL serve nothing, `assignmentsFail` makes the
 * assignment API fail while the workspace is still there, and the `forbid`
 * flags make one API answer 403, as it does for a principal without the role
 * it needs.
 */
const newFakeDatabricks = () => {
  const users = new Map<string, FakeUser>();
  const assignments = new Map<string, string[]>(); // userId -> permissions on the workspace
  const state = {
    ignoreWrites: false,
    workspaceUp: true,
    assignmentsFail: false,
    /** Whether account SCIM answers 403, as for a principal without account admin. */
    forbidAccount: false,
    /** Whether the workspace's SCIM proxy answers 403, as for a non-admin. */
    forbidProxy: false,
    /** Whether the workspace's assignment API answers 403, as for a non-admin. */
    forbidAssignments: false,
    /** Whether only its writes (`PUT` and `DELETE`) answer 403. */
    forbidAssignmentWrites: false,
    /**
     * Whether someone else removes an assignment just before P0's `DELETE`,
     * which then answers 404.
     */
    removedBeforeDelete: false,
    /** The workspace ID the workspace's metastore assignment answers with. */
    boundWorkspaceId: WORKSPACE_ID,
    /** The ID the workspace's `SCIM /Me` reports for the connector. */
    meId: SP_SCIM_ID,
  };

  const notFound = (errorCode?: string) =>
    jsonResponse(
      { detail: "not found", ...(errorCode ? { error_code: errorCode } : {}) },
      { status: 404, statusText: "Not Found" }
    );

  /** Account SCIM `Users`, on the account or through the workspace's proxy. */
  const scimUsers = (
    path: string,
    url: URL,
    method: string,
    body: unknown,
    { patches }: { patches: boolean }
  ) => {
    if (path === "" && method === "GET") {
      const filter = url.searchParams.get("filter") ?? "";
      const [, attribute, value] =
        /^(userName|emails\.value) eq "(.*)"$/.exec(filter) ?? [];
      const Resources = [...users.values()].filter((user) =>
        attribute === "userName"
          ? user.userName === value
          : (user.emails ?? []).some((email) => email.value === value)
      );
      return jsonResponse({ totalResults: Resources.length, Resources });
    }
    const [, scimId] = /^\/(\d+)$/.exec(path) ?? [];
    const user = scimId ? users.get(scimId) : undefined;
    if (!user) return notFound();
    if (method === "GET") return jsonResponse(user);
    if (method === "PATCH" && patches) {
      if (!state.ignoreWrites) {
        for (const op of scimPatch.parse(body).Operations) {
          if (op.op === "add" && op.value) {
            user.roles = [...(user.roles ?? []), ...op.value.roles];
          } else if (
            op.op === "remove" &&
            op.path === 'roles[value eq "account_admin"]'
          ) {
            user.roles = (user.roles ?? []).filter(
              (role) => role.value !== "account_admin"
            );
          }
        }
      }
      return jsonResponse(user);
    }
    return notFound();
  };

  const accountApi = (url: URL, method: string, body: unknown) => {
    const path = url.pathname.replace(`/api/2.0/accounts/${ACCOUNT_ID}`, "");
    if (path === "/scim/v2/Users" || path.startsWith("/scim/v2/Users/")) {
      if (state.forbidAccount) return forbidden();
      return scimUsers(path.slice("/scim/v2/Users".length), url, method, body, {
        patches: true,
      });
    }
    if (path === "/scim/v2/ServicePrincipals" && method === "GET") {
      return jsonResponse({
        totalResults: 1,
        Resources: [
          {
            id: SP_SCIM_ID,
            applicationId: APPLICATION_ID,
            displayName: "p0-connector",
          },
        ],
      });
    }
    return notFound();
  };

  const workspaceApi = (url: URL, method: string, body: unknown) => {
    // A deleted workspace's URL serves nothing, so a call to it never connects.
    if (!state.workspaceUp) throw new TypeError("fetch failed");
    const path = url.pathname;
    if (isBinding(url.href)) return bindingResponse(state.boundWorkspaceId);
    if (path === "/api/2.0/preview/scim/v2/Me" && method === "GET") {
      return jsonResponse({ id: state.meId, userName: APPLICATION_ID });
    }
    if (path === PROXY_USERS || path.startsWith(`${PROXY_USERS}/`)) {
      if (state.forbidProxy) return forbidden();
      return scimUsers(path.slice(PROXY_USERS.length), url, method, body, {
        patches: false,
      });
    }
    if (path !== ASSIGNMENTS && !path.startsWith(`${ASSIGNMENTS}/`)) {
      return notFound();
    }
    if (state.forbidAssignments) return forbidden();
    if (state.forbidAssignmentWrites && method !== "GET") return forbidden();
    if (state.assignmentsFail) {
      return jsonResponse(
        { error_code: "TEMPORARILY_UNAVAILABLE", message: "try later" },
        { status: 503 }
      );
    }
    if (path === ASSIGNMENTS && method === "GET") {
      return jsonResponse({
        permission_assignments: [...assignments].map(([id, permissions]) => ({
          principal: {
            principal_id: Number(id),
            user_name: users.get(id)?.userName,
          },
          permissions,
        })),
      });
    }
    const [, principalId] =
      new RegExp(`^${ASSIGNMENTS}/principals/(\\d+)$`).exec(path) ?? [];
    if (principalId && method === "PUT") {
      if (!state.ignoreWrites) {
        assignments.set(principalId, assignmentPut.parse(body).permissions);
      }
      return jsonResponse({});
    }
    if (principalId && method === "DELETE") {
      if (state.removedBeforeDelete) assignments.delete(principalId);
      if (!assignments.has(principalId)) return notFound();
      if (!state.ignoreWrites) assignments.delete(principalId);
      return jsonResponse(undefined);
    }
    return notFound();
  };

  const handler = (rawUrl: string, init: RequestInit) => {
    const url = new URL(rawUrl);
    const method = init.method ?? "GET";
    const body: unknown =
      typeof init.body === "string" ? JSON.parse(init.body) : undefined;
    if (url.origin === ACCOUNTS_URL) return accountApi(url, method, body);
    if (url.origin === WORKSPACE_URL) return workspaceApi(url, method, body);
    return notFound();
  };

  return { users, assignments, state, handler };
};

let databricks: ReturnType<typeof newFakeDatabricks>;
let fetchMock: ReturnType<typeof stubFetch>;

const admin = () =>
  connectorRouter.createCaller({ logger: createLogger() }).databricks.accesses
    .admin;

/** A workspace admin request's context. Its `operation` is `grant` unless overridden. */
const workspaceContext = (
  overrides: Partial<RequestContext> = {}
): RequestContext => ({
  ...accountContext(),
  workspaceId: WORKSPACE_ID,
  workspaceUrl: WORKSPACE_URL,
  priorAssignment: "none",
  operation: "grant",
  ...overrides,
});

/** An account admin request's context. Its `operation` is `grant` unless overridden. */
const accountAdminContext = (
  overrides: Partial<RequestContext> = {}
): RequestContext => ({
  ...accountContext(),
  priorAssignment: "none",
  operation: "grant",
  ...overrides,
});

/** The role a context's scope carries: workspace admin when it names a workspace. */
const roleOf = (context: RequestContext): Policy =>
  context.workspaceId ? "WORKSPACE_ADMIN" : "ACCOUNT_ADMIN";

/**
 * The user body P0 sends with a user ID: the requestor's email and the
 * account SCIM ID it recorded at stage.
 */
const recordedBody = (userId = ALICE_ID): UserBody => ({
  email: ALICE,
  userId,
});

const setPolicies = (
  context: RequestContext,
  policies: Policy[],
  userId = ALICE_ID
) =>
  admin().setPoliciesForUser({
    userId,
    userBody: recordedBody(userId),
    policies,
    context,
  });

/** Grants the scope's role. */
const grant = (
  context: RequestContext,
  policies: Policy[] = [roleOf(context)],
  userId?: string
) => setPolicies({ ...context, operation: "grant" }, policies, userId);

/**
 * Revokes the scope's role. `policies` still holds it while another open
 * request on the scope does.
 */
const revoke = (
  context: RequestContext,
  policies: Policy[] = [],
  userId?: string
) => setPolicies({ ...context, operation: "revoke" }, policies, userId);

const list = (query: ListerQuery) => admin().list({ query });

/** A workspace `priorAssignment` query for Alice. */
const workspaceQuery = (overrides: Partial<ListerQuery> = {}): ListerQuery => ({
  type: "priorAssignment",
  context: accountContext(),
  userId: ALICE_ID,
  workspaceId: WORKSPACE_ID,
  workspaceUrl: WORKSPACE_URL,
  ...overrides,
});

/**
 * The Databricks calls made, other than token exchanges, as `METHOD path`.
 * Account paths drop the `/api/2.0/accounts/<id>` prefix, and workspace paths
 * keep their full path, so the two never look alike.
 */
const databricksCalls = () =>
  fetchCalls(fetchMock)
    .filter((call) => !isTokenExchange(call))
    .map((call) => ({
      route: `${call.init.method} ${new URL(call.url).pathname.replace(
        `/api/2.0/accounts/${ACCOUNT_ID}`,
        ""
      )}`,
      body: call.init.body ? JSON.parse(call.init.body) : undefined,
    }));

const routes = () => databricksCalls().map(({ route }) => route);

const writes = () =>
  databricksCalls().filter(({ route }) => !route.startsWith("GET "));

/** The URLs of every call but the token exchange. */
const callUrls = () =>
  fetchCalls(fetchMock)
    .filter((call) => !isTokenExchange(call))
    .map((call) => call.url);

const assignmentRoute = `${ASSIGNMENTS}/principals/${ALICE_ID}`;
const bindingRoute = `GET ${METASTORE_ASSIGNMENT}`;

const domainRefusal = (userName: string) => ({
  message: `Domain verification refused ${userName}: DOMAIN_PATTERN on the connector must match the whole domain after the @.`,
  data: { type: "validation_error" },
});

const notAUser = (userId: string) => ({
  message: `P0 grants Databricks admin roles only to users, and ${userId} is not a user in this account`,
  data: { type: "validation_error" },
});

const notWorkspaceAdmin = {
  message: `P0's service principal isn't an admin of Databricks workspace ${WORKSPACE_ID}, so P0 can't manage workspace admin there. Turn on workspace-admin requests for the workspace in P0, and apply the Terraform that P0 shows.`,
  data: { type: "insufficient_privileges" },
};

const notAccountAdmin = {
  message: `P0's service principal isn't an account admin in Databricks account ${ACCOUNT_ID}, so P0 can't manage account admin there. Turn on account-admin requests for the account in P0, and apply the Terraform that P0 shows.`,
  data: { type: "insufficient_privileges" },
};

const unreachableOnRevoke = (type: string) => ({
  message: `P0 can't reach Databricks workspace ${WORKSPACE_ID} at ${WORKSPACE_URL} to revoke workspace admin. If the workspace was deleted, the user's admin role went with it.`,
  data: {
    type,
    payload: { workspaceId: WORKSPACE_ID, workspaceUrl: WORKSPACE_URL },
  },
});

const narrowPattern = () => vi.stubEnv(DOMAIN_PATTERN_ENV, "other\\.com");

beforeEach(() => {
  vi.stubEnv(DOMAIN_PATTERN_ENV, "example\\.com");

  databricks = newFakeDatabricks();
  databricks.users.set(ALICE_ID, {
    id: ALICE_ID,
    userName: ALICE,
    emails: [{ value: ALICE }],
  });
  fetchMock = stubFetch(databricks.handler);
  warn.mockClear();
});

afterEach(() => {
  // P0 never puts a user in a group, in any operation.
  expect(fetchCalls(fetchMock).some(({ url }) => /groups/i.test(url))).toBe(
    false
  );
});

describe("workspace admin", () => {
  it("binds, finds the user through the workspace's SCIM proxy, and grants with PUT [ADMIN] on the workspace assignment API", async () => {
    await grant(workspaceContext());

    expect(databricks.assignments.get(ALICE_ID)).toEqual(["ADMIN"]);
    expect(routes()).toEqual([
      bindingRoute,
      `GET ${PROXY_USERS}/${ALICE_ID}`,
      "GET /api/2.0/preview/scim/v2/Me",
      `GET ${ASSIGNMENTS}`,
      `PUT ${assignmentRoute}`,
      `GET ${ASSIGNMENTS}`,
    ]);
    expect(writes()).toEqual([
      { route: `PUT ${assignmentRoute}`, body: { permissions: ["ADMIN"] } },
    ]);
    // Every call but the token exchange goes to the workspace.
    expect(callUrls().every((url) => url.startsWith(`${WORKSPACE_URL}/`))).toBe(
      true
    );
  });

  it("grants over an existing USER assignment", async () => {
    databricks.assignments.set(ALICE_ID, ["USER"]);

    await grant(workspaceContext({ priorAssignment: "USER" }));

    expect(databricks.assignments.get(ALICE_ID)).toEqual(["ADMIN"]);
  });

  describe("refuses a grant when the assignment changed since approval", () => {
    it.each([
      ["none", ["USER"], "USER"],
      ["USER", undefined, "none"],
    ] as const)(
      "approved as %s, now %j",
      async (priorAssignment, permissions, current) => {
        if (permissions) databricks.assignments.set(ALICE_ID, [...permissions]);

        await expect(
          grant(workspaceContext({ priorAssignment }))
        ).rejects.toMatchObject({
          message: `The user's workspace assignment changed since the request was approved (it was ${priorAssignment}, it is now ${current}). Resubmit the request.`,
          data: { type: "validation_error" },
        });
        expect(writes()).toEqual([]);
      }
    );
  });

  it("writes nothing when the user is already admin", async () => {
    databricks.assignments.set(ALICE_ID, ["ADMIN"]);

    await grant(workspaceContext());

    expect(writes()).toEqual([]);
  });

  describe("revoke restores the prior assignment", () => {
    it("deletes the assignment when the user had none", async () => {
      databricks.assignments.set(ALICE_ID, ["ADMIN"]);

      await revoke(workspaceContext({ priorAssignment: "none" }));

      expect(databricks.assignments.has(ALICE_ID)).toBe(false);
      expect(writes()).toEqual([
        { route: `DELETE ${assignmentRoute}`, body: undefined },
      ]);
    });

    it("counts a DELETE that finds the assignment already gone as removed", async () => {
      databricks.assignments.set(ALICE_ID, ["ADMIN"]);
      databricks.state.removedBeforeDelete = true;

      await expect(
        revoke(workspaceContext({ priorAssignment: "none" }))
      ).resolves.toBeNull();
      expect(databricks.assignments.has(ALICE_ID)).toBe(false);
    });

    it("puts [USER] back when the user was a workspace user", async () => {
      databricks.assignments.set(ALICE_ID, ["ADMIN"]);

      await revoke(workspaceContext({ priorAssignment: "USER" }));

      expect(databricks.assignments.get(ALICE_ID)).toEqual(["USER"]);
      expect(writes()).toEqual([
        { route: `PUT ${assignmentRoute}`, body: { permissions: ["USER"] } },
      ]);
    });
  });

  describe("revoke does nothing once the user is no longer admin", () => {
    it("leaves a user someone demoted to USER alone", async () => {
      databricks.assignments.set(ALICE_ID, ["USER"]);

      await revoke(workspaceContext({ priorAssignment: "none" }));

      expect(databricks.assignments.get(ALICE_ID)).toEqual(["USER"]);
      expect(writes()).toEqual([]);
    });

    it("leaves a user someone removed from the workspace alone", async () => {
      await revoke(workspaceContext({ priorAssignment: "USER" }));

      expect(databricks.assignments.has(ALICE_ID)).toBe(false);
      expect(writes()).toEqual([]);
    });
  });

  it("leaves the role in place on a revoke while another open request on the workspace holds it", async () => {
    databricks.assignments.set(ALICE_ID, ["ADMIN"]);

    await expect(
      revoke(workspaceContext(), ["WORKSPACE_ADMIN"])
    ).resolves.toBeNull();

    expect(databricks.assignments.get(ALICE_ID)).toEqual(["ADMIN"]);
    expect(writes()).toEqual([]);
  });

  // A workspace that answers wrongly may still hold the role, so a revoke
  // that can't bind never counts as done.
  describe("a revoke whose workspace can't be bound", () => {
    beforeEach(() => {
      databricks.assignments.set(ALICE_ID, ["ADMIN"]);
    });

    it("fails saying P0 can't reach the workspace, keeping the binding error as its cause", async () => {
      databricks.state.workspaceUp = false;

      const error: unknown = await revoke(workspaceContext()).catch(
        (e: unknown) => e
      );

      expect(error).toMatchObject(unreachableOnRevoke("upstream_unavailable"));
      expect(error).toHaveProperty(
        "cause.data.message",
        `Databricks GET ${METASTORE_ASSIGNMENT} failed: fetch failed`
      );
      expect(callUrls().some((url) => url.startsWith(ACCOUNTS_URL))).toBe(
        false
      );
    });

    it("keeps validation_error when the URL now answers for another workspace", async () => {
      databricks.state.boundWorkspaceId = "42";

      await expect(revoke(workspaceContext())).rejects.toMatchObject(
        unreachableOnRevoke("validation_error")
      );
      expect(writes()).toEqual([]);
      expect(databricks.assignments.get(ALICE_ID)).toEqual(["ADMIN"]);
    });

    it("says the same on the lookup by recorded ID that precedes a revoke", async () => {
      databricks.state.workspaceUp = false;

      await expect(
        admin().identifyUser({
          userBody: { email: ALICE, userId: ALICE_ID },
          context: workspaceContext({ operation: "revoke" }),
        })
      ).rejects.toMatchObject(unreachableOnRevoke("upstream_unavailable"));
    });

    it("fails a grant with the binding's own error", async () => {
      databricks.state.workspaceUp = false;

      await expect(grant(workspaceContext())).rejects.toMatchObject({
        message: `Databricks GET ${METASTORE_ASSIGNMENT} failed: fetch failed`,
        data: { type: "upstream_unavailable" },
      });
    });
  });

  it("still fails a revoke while the assignment API is down", async () => {
    databricks.assignments.set(ALICE_ID, ["ADMIN"]);
    databricks.state.assignmentsFail = true;

    await expect(revoke(workspaceContext())).rejects.toMatchObject({
      data: { type: "upstream_unavailable", payload: { status: 503 } },
    });
  });

  describe("a principal that isn't an admin of the workspace", () => {
    it("is refused with the workspace message when the SCIM proxy answers 403", async () => {
      databricks.state.forbidProxy = true;

      await expect(grant(workspaceContext())).rejects.toMatchObject(
        notWorkspaceAdmin
      );
      await expect(
        admin().identifyUser({
          userBody: { email: ALICE },
          context: workspaceContext(),
        })
      ).rejects.toMatchObject(notWorkspaceAdmin);
    });

    it.each([
      ["a grant's read", (ctx: RequestContext) => grant(ctx)],
      ["a revoke's read", (ctx: RequestContext) => revoke(ctx)],
      ["the priorAssignment lister", () => list(workspaceQuery())],
    ])(
      "is refused with the workspace message when the assignment API answers %s with 403",
      async (_, call) => {
        databricks.assignments.set(ALICE_ID, ["ADMIN"]);
        databricks.state.forbidAssignments = true;

        await expect(call(workspaceContext())).rejects.toMatchObject(
          notWorkspaceAdmin
        );
        expect(writes()).toEqual([]);
      }
    );

    it("is refused with the workspace message when the assignment API answers a PUT with 403", async () => {
      databricks.state.forbidAssignmentWrites = true;

      await expect(grant(workspaceContext())).rejects.toMatchObject(
        notWorkspaceAdmin
      );
    });

    it("is refused with the workspace message when the assignment API answers a DELETE with 403", async () => {
      databricks.assignments.set(ALICE_ID, ["ADMIN"]);
      databricks.state.forbidAssignmentWrites = true;

      await expect(revoke(workspaceContext())).rejects.toMatchObject(
        notWorkspaceAdmin
      );
      expect(databricks.assignments.get(ALICE_ID)).toEqual(["ADMIN"]);
    });
  });

  it("fails when the read-back doesn't show the change", async () => {
    databricks.state.ignoreWrites = true;

    await expect(grant(workspaceContext())).rejects.toMatchObject({
      data: { type: "unknown" },
    });
  });

  it("matches the user's assignment by user name when the principal ID lost precision", async () => {
    const bigId = "9007199254740993"; // 2^53 + 1, which JSON parsing rounds
    databricks.users.set(bigId, { id: bigId, userName: "bob@example.com" });
    databricks.assignments.set(bigId, ["ADMIN"]);

    await expect(list(workspaceQuery({ userId: bigId }))).resolves.toEqual([
      { key: "ADMIN", value: "Workspace admin" },
    ]);
  });
});

describe("account admin", () => {
  it("adds account_admin to the user's SCIM roles and reads it back", async () => {
    await grant(accountAdminContext());

    expect(databricks.users.get(ALICE_ID)?.roles).toEqual([
      { value: "account_admin" },
    ]);
    expect(writes()).toEqual([
      {
        route: `PATCH /scim/v2/Users/${ALICE_ID}`,
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [
            { op: "add", value: { roles: [{ value: "account_admin" }] } },
          ],
        },
      },
    ]);
    expect(databricksCalls().at(-1)?.route).toBe(
      `GET /scim/v2/Users/${ALICE_ID}`
    );
    // Account admin never touches a workspace.
    expect(callUrls().every((url) => url.startsWith(`${ACCOUNTS_URL}/`))).toBe(
      true
    );
  });

  it.each([
    ["a grant", () => grant(accountAdminContext())],
    ["a revoke", () => revoke(accountAdminContext())],
    [
      "the priorAssignment lister",
      () =>
        list({
          type: "priorAssignment",
          context: accountContext(),
          userId: ALICE_ID,
        }),
    ],
  ])(
    "refuses %s with the account message when account SCIM answers 403",
    async (_, call) => {
      databricks.state.forbidAccount = true;

      await expect(call()).rejects.toMatchObject(notAccountAdmin);
      expect(writes()).toEqual([]);
    }
  );

  it("writes nothing when the user is already account admin", async () => {
    databricks.users.get(ALICE_ID)!.roles = [{ value: "account_admin" }];

    await grant(accountAdminContext());

    expect(writes()).toEqual([]);
  });

  it("revokes by removing account_admin from the user's SCIM roles", async () => {
    databricks.users.get(ALICE_ID)!.roles = [{ value: "account_admin" }];

    await revoke(accountAdminContext());

    expect(databricks.users.get(ALICE_ID)?.roles).toEqual([]);
    expect(writes()).toEqual([
      {
        route: `PATCH /scim/v2/Users/${ALICE_ID}`,
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [
            { op: "remove", path: 'roles[value eq "account_admin"]' },
          ],
        },
      },
    ]);
  });

  it("does nothing on revoke when account_admin is already gone", async () => {
    await revoke(accountAdminContext());

    expect(writes()).toEqual([]);
  });

  it("leaves the role in place on a revoke while another open request holds it", async () => {
    databricks.users.get(ALICE_ID)!.roles = [{ value: "account_admin" }];

    await expect(
      revoke(accountAdminContext(), ["ACCOUNT_ADMIN"])
    ).resolves.toBeNull();

    expect(databricks.users.get(ALICE_ID)?.roles).toEqual([
      { value: "account_admin" },
    ]);
    expect(writes()).toEqual([]);
  });

  it("fails when the read-back still shows the role", async () => {
    databricks.users.get(ALICE_ID)!.roles = [{ value: "account_admin" }];
    databricks.state.ignoreWrites = true;

    await expect(revoke(accountAdminContext())).rejects.toMatchObject({
      data: { type: "unknown" },
    });
  });
});

// When a grant fails partway, the control plane rolls it back on the same
// request, so those calls still say "grant". Unless another open request on
// the scope holds the role, they carry no policy.
describe("a call labeled grant with no policy, as a rollback's is", () => {
  const rollBack = (context: RequestContext) => grant(context, []);

  it.each([
    ["none", undefined],
    ["USER", ["USER"]],
  ] as const)(
    "restores the prior workspace assignment %s",
    async (priorAssignment, permissions) => {
      databricks.assignments.set(ALICE_ID, ["ADMIN"]);

      await expect(
        rollBack(workspaceContext({ priorAssignment }))
      ).resolves.toBeNull();

      expect(databricks.assignments.get(ALICE_ID)).toEqual(permissions);
    }
  );

  it("removes account_admin", async () => {
    databricks.users.get(ALICE_ID)!.roles = [{ value: "account_admin" }];

    await expect(rollBack(accountAdminContext())).resolves.toBeNull();

    expect(databricks.users.get(ALICE_ID)?.roles).toEqual([]);
  });

  it.each([
    ["the pattern narrows", narrowPattern],
    ["the pattern is unset", () => vi.stubEnv(DOMAIN_PATTERN_ENV, undefined)],
    ["the pattern is invalid", () => vi.stubEnv(DOMAIN_PATTERN_ENV, "(other")],
  ])("isn't refused after %s", async (_, changePattern) => {
    databricks.assignments.set(ALICE_ID, ["ADMIN"]);
    databricks.users.get(ALICE_ID)!.roles = [{ value: "account_admin" }];
    changePattern();

    for (const context of [workspaceContext(), accountAdminContext()]) {
      await expect(rollBack(context)).resolves.toBeNull();
    }

    expect(databricks.assignments.has(ALICE_ID)).toBe(false);
    expect(databricks.users.get(ALICE_ID)?.roles).toEqual([]);
    expect(domainWarnings()).toBe(2);
  });

  it("only ever lowers access", async () => {
    // A user who is admin nowhere, and a prior assignment of USER that
    // doesn't match the workspace.
    await expect(
      rollBack(workspaceContext({ priorAssignment: "USER" }))
    ).resolves.toBeNull();
    await expect(rollBack(accountAdminContext())).resolves.toBeNull();

    expect(databricks.assignments.has(ALICE_ID)).toBe(false);
    expect(databricks.users.get(ALICE_ID)?.roles ?? []).toEqual([]);
    expect(writes()).toEqual([]);
  });

  it("warns once that it takes the call for a failed grant's rollback", async () => {
    databricks.assignments.set(ALICE_ID, ["ADMIN"]);

    await expect(rollBack(workspaceContext())).resolves.toBeNull();

    expect(warn.mock.calls).toEqual([
      [
        "call says grant but carries no policy; treating it as the rollback of a failed grant",
      ],
    ]);
  });

  it("warns about neither a grant nor a revoke whose label agrees", async () => {
    await grant(workspaceContext());
    await revoke(workspaceContext());

    expect(warn).not.toHaveBeenCalled();
  });

  // The validation hook reads the grantee before the policies say this is
  // a revoke, so the binding fails as itself. It is never counted as done.
  it("fails when it can't bind its workspace", async () => {
    databricks.assignments.set(ALICE_ID, ["ADMIN"]);
    databricks.state.workspaceUp = false;

    await expect(rollBack(workspaceContext())).rejects.toMatchObject({
      data: { type: "upstream_unavailable" },
    });
    expect(databricks.assignments.get(ALICE_ID)).toEqual(["ADMIN"]);
  });
});

describe("refusals", () => {
  it("refuses the connector's own service principal, which is not a user", async () => {
    await expect(
      grant(accountAdminContext(), ["ACCOUNT_ADMIN"], SP_SCIM_ID)
    ).rejects.toMatchObject(notAUser(SP_SCIM_ID));
    expect(writes()).toEqual([]);
  });

  it("compares with the workspace's SCIM /Me in the workspace scope, not with account SCIM", async () => {
    // The workspace reports the connector under another ID than account SCIM
    // does, so each scope can only refuse this user by its own lookup.
    const otherId = "5555555555555555";
    databricks.state.meId = otherId;
    databricks.users.set(otherId, {
      id: otherId,
      userName: "p0-workspace@example.com",
    });

    await expect(
      grant(workspaceContext(), ["WORKSPACE_ADMIN"], otherId)
    ).rejects.toMatchObject({
      message: "P0 cannot grant access to its own Databricks service principal",
    });
    await expect(
      grant(accountAdminContext(), ["ACCOUNT_ADMIN"], otherId)
    ).resolves.toBeNull();
    expect(routes()).toContain("GET /api/2.0/preview/scim/v2/Me");
  });

  it("refuses a user carrying the connector's own principal ID, as defence in depth", async () => {
    // Databricks gives every principal its own ID, and account SCIM `Users`
    // never lists a service principal, so only a misbehaving API could
    // return this user.
    databricks.users.set(SP_SCIM_ID, {
      id: SP_SCIM_ID,
      userName: "p0-connector@example.com",
      roles: [{ value: "account_admin" }],
    });
    databricks.assignments.set(SP_SCIM_ID, ["ADMIN"]);

    for (const context of [workspaceContext(), accountAdminContext()]) {
      for (const call of [
        () => grant(context, [roleOf(context)], SP_SCIM_ID),
        () => revoke(context, [], SP_SCIM_ID),
        // A revoke another open request covers, which changes nothing.
        () => revoke(context, [roleOf(context)], SP_SCIM_ID),
      ]) {
        await expect(call()).rejects.toMatchObject({
          data: {
            type: "validation_error",
            message:
              "P0 cannot grant access to its own Databricks service principal",
          },
        });
      }
    }
    expect(writes()).toEqual([]);
  });

  it("refuses a grantee that isn't a user, such as a group", async () => {
    // The fake has no user with GROUP_ID, as account SCIM Users wouldn't.
    await expect(
      grant(workspaceContext(), ["WORKSPACE_ADMIN"], GROUP_ID)
    ).rejects.toMatchObject(notAUser(GROUP_ID));
    expect(writes()).toEqual([]);
  });

  it.each([
    ["workspace", workspaceContext, `GET ${PROXY_USERS}/${ALICE_ID}`],
    ["account", accountAdminContext, `GET /scim/v2/Users/${ALICE_ID}`],
  ])(
    "reads the grantee once per call in the %s scope",
    async (_, context, route) => {
      await grant(context());

      // Account admin reads the user again after its write, to confirm it.
      const beforeWrite = routes().slice(
        0,
        routes().findIndex((r) => !r.startsWith("GET "))
      );
      expect(beforeWrite.filter((r) => r === route)).toHaveLength(1);
    }
  );

  it("refuses a user outside DOMAIN_PATTERN, saying why", async () => {
    databricks.users.set(ALICE_ID, {
      id: ALICE_ID,
      userName: "alice@evil.io",
      emails: [{ value: "alice@evil.io" }],
    });

    for (const context of [workspaceContext(), accountAdminContext()]) {
      await expect(grant(context)).rejects.toMatchObject(
        domainRefusal("alice@evil.io")
      );
    }
    expect(writes()).toEqual([]);
  });

  it("checks the userName, not an email that matches the pattern", async () => {
    databricks.users.set(ALICE_ID, {
      id: ALICE_ID,
      userName: "alice@contoso.onmicrosoft.com",
      emails: [{ value: ALICE }],
    });

    await expect(grant(workspaceContext())).rejects.toMatchObject(
      domainRefusal("alice@contoso.onmicrosoft.com")
    );
    expect(writes()).toEqual([]);
  });

  it("refuses every user when DOMAIN_PATTERN is unset, saying domain verification isn't configured", async () => {
    vi.stubEnv(DOMAIN_PATTERN_ENV, undefined);

    await expect(grant(workspaceContext())).rejects.toMatchObject({
      message: expect.stringMatching(
        /^Domain verification is not configured: DOMAIN_PATTERN is not set/
      ),
      data: { type: "validation_error" },
    });
    expect(writes()).toEqual([]);
  });

  it("refuses to look up an email outside DOMAIN_PATTERN", async () => {
    await expect(
      admin().identifyUser({
        userBody: { email: "alice@evil.io" },
        context: workspaceContext(),
      })
    ).rejects.toMatchObject(domainRefusal("alice@evil.io"));
    expect(databricksCalls()).toEqual([]);
  });

  it("rejects a policy that doesn't match the resource", async () => {
    await expect(
      grant(workspaceContext(), ["ACCOUNT_ADMIN"])
    ).rejects.toMatchObject({ data: { type: "unknown" } });
    await expect(
      grant(accountAdminContext(), ["WORKSPACE_ADMIN"])
    ).rejects.toMatchObject({ data: { type: "unknown" } });
    expect(writes()).toEqual([]);
  });

  it.each([
    ["workspace ID", { workspaceId: "../../evil" }, ALICE_ID],
    ["user ID", {}, "1/../2"],
    ["workspace URL", { workspaceUrl: "https://evil.example" }, ALICE_ID],
  ])(
    "rejects a bad %s before calling Databricks",
    async (_, overrides, userId) => {
      await expect(
        grant(workspaceContext(overrides), ["WORKSPACE_ADMIN"], userId)
      ).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );
});

// Half a workspace pair must never be read as the account scope, which would
// grant or revoke account admin instead.
describe("the workspace pair", () => {
  const { workspaceUrl: _url, ...onlyId } = workspaceContext();
  const { workspaceId: _id, ...onlyUrl } = workspaceContext();

  it.each([
    ["a workspace ID without its URL", onlyId],
    ["a URL without its workspace ID", onlyUrl],
  ])("refuses %s in the request context", async (_, context) => {
    expect(() => spec.requestContext(context)).toThrow(WORKSPACE_PAIR_ERROR);
    for (const call of [
      () => grant(context, ["WORKSPACE_ADMIN"]),
      () => grant(context, ["ACCOUNT_ADMIN"]),
      () => revoke(context),
      () => admin().identifyUser({ userBody: { email: ALICE }, context }),
    ]) {
      await expect(call()).rejects.toThrow(WORKSPACE_PAIR_ERROR);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["a workspace ID without its URL", { workspaceUrl: undefined }],
    ["a URL without its workspace ID", { workspaceId: undefined }],
  ])("refuses %s in the lister query", async (_, overrides) => {
    const query = workspaceQuery(overrides);

    expect(() => spec.listerQuery(query)).toThrow(WORKSPACE_PAIR_ERROR);
    await expect(list(query)).rejects.toThrow(WORKSPACE_PAIR_ERROR);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // The parsers refuse half a pair first. The handler refuses it again, so
  // even a caller that skipped them can't reach the account scope.
  it.each([[{ workspaceId: WORKSPACE_ID }], [{ workspaceUrl: WORKSPACE_URL }]])(
    "is refused again by the handler's scope check: %j",
    (half) => {
      expect(() => adminScopeOf({ ...accountContext(), ...half })).toThrow(
        WORKSPACE_PAIR_ERROR
      );
    }
  );

  it("names the account scope only when both are absent", () => {
    expect(adminScopeOf(accountContext())).toEqual({ kind: "account" });
    expect(
      adminScopeOf({
        ...accountContext(),
        workspaceId: WORKSPACE_ID,
        workspaceUrl: WORKSPACE_URL,
      })
    ).toEqual({
      kind: "workspace",
      workspaceId: WORKSPACE_ID,
      workspaceUrl: WORKSPACE_URL,
    });
  });
});

describe("domain verification on revoke", () => {
  const identifyByRecordedId = () =>
    admin().identifyUser({
      userBody: { email: ALICE, userId: ALICE_ID },
      context: workspaceContext({ operation: "revoke" }),
    });

  describe.each([
    ["the pattern narrows", narrowPattern],
    ["the pattern is unset", () => vi.stubEnv(DOMAIN_PATTERN_ENV, undefined)],
    ["the pattern is invalid", () => vi.stubEnv(DOMAIN_PATTERN_ENV, "(other")],
  ])("after %s", (_, changePattern) => {
    it("revokes workspace admin from a user found by recorded identity, warning once", async () => {
      databricks.assignments.set(ALICE_ID, ["ADMIN"]);
      changePattern();

      await expect(identifyByRecordedId()).resolves.toBe(ALICE_ID);
      // The lookup by recorded identity checks nothing and logs nothing.
      expect(domainWarnings()).toBe(0);
      await expect(
        revoke(workspaceContext({ priorAssignment: "none" }))
      ).resolves.toBeNull();
      expect(domainWarnings()).toBe(1);

      expect(databricks.assignments.has(ALICE_ID)).toBe(false);
    });

    it("revokes account admin", async () => {
      databricks.users.get(ALICE_ID)!.roles = [{ value: "account_admin" }];
      changePattern();

      await expect(revoke(accountAdminContext())).resolves.toBeNull();

      expect(databricks.users.get(ALICE_ID)?.roles).toEqual([]);
    });

    it("lets the first of two open requests on a scope go, changing nothing", async () => {
      databricks.assignments.set(ALICE_ID, ["ADMIN"]);
      databricks.users.get(ALICE_ID)!.roles = [{ value: "account_admin" }];
      changePattern();

      // The other request still holds the role, so the revoke's policies
      // still carry it.
      for (const context of [workspaceContext(), accountAdminContext()]) {
        await expect(revoke(context, [roleOf(context)])).resolves.toBeNull();
      }

      expect(writes()).toEqual([]);
      expect(databricks.assignments.get(ALICE_ID)).toEqual(["ADMIN"]);
      expect(databricks.users.get(ALICE_ID)?.roles).toEqual([
        { value: "account_admin" },
      ]);
    });
  });

  it("still refuses an email-only lookup once the user no longer passes", async () => {
    narrowPattern();

    await expect(
      admin().identifyUser({
        userBody: { email: ALICE },
        context: workspaceContext({ operation: "revoke" }),
      })
    ).rejects.toMatchObject(domainRefusal(ALICE));
  });

  // The framework runs the body check before `setPoliciesForUser` and
  // `deleteUser` too. A body without the recorded ID is checked by its email,
  // and on a revoke that check only warns.
  describe("a body carrying only the email", () => {
    const emailOnly = { email: ALICE };

    it("revokes, warning rather than refusing", async () => {
      databricks.assignments.set(ALICE_ID, ["ADMIN"]);
      narrowPattern();

      await expect(
        admin().setPoliciesForUser({
          userId: ALICE_ID,
          userBody: emailOnly,
          policies: [],
          context: workspaceContext({
            operation: "revoke",
            priorAssignment: "none",
          }),
        })
      ).resolves.toBeNull();
      // One from the body check, one from the revoke itself.
      expect(domainWarnings()).toBe(2);
      expect(databricks.assignments.has(ALICE_ID)).toBe(false);
    });

    it("lets deleteUser through on a revoke", async () => {
      narrowPattern();

      await expect(
        admin().deleteUser({
          userId: ALICE_ID,
          userBody: emailOnly,
          context: workspaceContext({ operation: "revoke" }),
        })
      ).resolves.toBeNull();
      expect(domainWarnings()).toBe(1);
      expect(writes()).toEqual([]);
    });

    it("still refuses a grant", async () => {
      narrowPattern();

      await expect(
        admin().setPoliciesForUser({
          userId: ALICE_ID,
          userBody: emailOnly,
          policies: ["WORKSPACE_ADMIN"],
          context: workspaceContext(),
        })
      ).rejects.toMatchObject(domainRefusal(ALICE));
      expect(writes()).toEqual([]);
    });
  });

  it("still refuses a grant once the user no longer passes, even found by recorded identity", async () => {
    narrowPattern();

    // The lookup by recorded identity only finds the user...
    await expect(
      admin().provisionUser({
        userBody: { email: ALICE, userId: ALICE_ID },
        context: workspaceContext(),
      })
    ).resolves.toBe(ALICE_ID);
    // ...and each grant itself is refused, before anything is written.
    for (const context of [workspaceContext(), accountAdminContext()]) {
      await expect(grant(context)).rejects.toMatchObject(domainRefusal(ALICE));
    }
    expect(writes()).toEqual([]);
  });

  it("refuses a grant for a user who no longer passes even when they already hold the role", async () => {
    databricks.assignments.set(ALICE_ID, ["ADMIN"]);
    databricks.users.get(ALICE_ID)!.roles = [{ value: "account_admin" }];
    narrowPattern();

    // Refusing a grant that would write nothing is what stops a user outside
    // the pattern keeping the role by asking again.
    for (const context of [workspaceContext(), accountAdminContext()]) {
      await expect(grant(context)).rejects.toMatchObject(domainRefusal(ALICE));
    }
    expect(writes()).toEqual([]);
  });

  describe("a revoke for a user who no longer passes only ever lowers access", () => {
    beforeEach(narrowPattern);

    it("creates nothing for a forged revoke with priorAssignment USER and no assignment", async () => {
      await expect(
        revoke(workspaceContext({ priorAssignment: "USER" }))
      ).resolves.toBeNull();

      expect(databricks.assignments.has(ALICE_ID)).toBe(false);
      expect(writes()).toEqual([]);
    });

    it("leaves a USER assignment alone, whatever priorAssignment says", async () => {
      databricks.assignments.set(ALICE_ID, ["USER"]);

      await revoke(workspaceContext({ priorAssignment: "none" }));

      expect(databricks.assignments.get(ALICE_ID)).toEqual(["USER"]);
      expect(writes()).toEqual([]);
    });

    it("lowers ADMIN to the recorded prior USER", async () => {
      databricks.assignments.set(ALICE_ID, ["ADMIN"]);

      await revoke(workspaceContext({ priorAssignment: "USER" }));

      expect(databricks.assignments.get(ALICE_ID)).toEqual(["USER"]);
    });

    it("never adds account_admin on revoke", async () => {
      await revoke(accountAdminContext());

      expect(databricks.users.get(ALICE_ID)?.roles ?? []).toEqual([]);
      expect(writes()).toEqual([]);
    });
  });
});

describe("users", () => {
  it("finds a workspace admin's user by userName through the workspace's SCIM proxy, after binding", async () => {
    await expect(
      admin().identifyUser({
        userBody: { email: ALICE },
        context: workspaceContext(),
      })
    ).resolves.toBe(ALICE_ID);
    expect(routes()).toEqual([bindingRoute, `GET ${PROXY_USERS}`]);
    expect(callUrls().every((url) => url.startsWith(WORKSPACE_URL))).toBe(true);
  });

  it("finds an account admin's user by userName through account SCIM", async () => {
    await expect(
      admin().identifyUser({
        userBody: { email: ALICE },
        context: accountAdminContext(),
      })
    ).resolves.toBe(ALICE_ID);
    expect(routes()).toEqual(["GET /scim/v2/Users"]);
  });

  it("falls back to emails.value, then checks the userName it found", async () => {
    databricks.users.set(ALICE_ID, {
      id: ALICE_ID,
      userName: "alice@contoso.onmicrosoft.com",
      emails: [{ value: ALICE }],
    });
    const identify = () =>
      admin().identifyUser({
        userBody: { email: ALICE },
        context: workspaceContext(),
      });

    await expect(identify()).rejects.toMatchObject(
      domainRefusal("alice@contoso.onmicrosoft.com")
    );

    vi.stubEnv(DOMAIN_PATTERN_ENV, "example\\.com|contoso\\.onmicrosoft\\.com");
    await expect(identify()).resolves.toBe(ALICE_ID);
  });

  it("escapes the email in the SCIM filter", async () => {
    await admin().identifyUser({
      userBody: { email: "o'brien@example.com" },
      context: workspaceContext(),
    });

    expect(
      callUrls()
        .filter((url) => url.includes(PROXY_USERS))
        .map((url) => new URL(url).searchParams.get("filter"))
    ).toEqual([
      `userName eq "o'brien@example.com"`,
      `emails.value eq "o'brien@example.com"`,
    ]);
  });

  describe("by the account SCIM ID P0 recorded", () => {
    const identifyById = (
      userId: string,
      email = "alice.new@example.com",
      operation: RequestContext["operation"] = "grant"
    ) =>
      admin().identifyUser({
        userBody: { email, userId },
        context: workspaceContext({ operation }),
      });

    it("reads the user by ID alone, ignoring an email that has since changed", async () => {
      await expect(identifyById(ALICE_ID)).resolves.toBe(ALICE_ID);
      expect(routes()).toEqual([
        bindingRoute,
        `GET ${PROXY_USERS}/${ALICE_ID}`,
      ]);
    });

    it("returns null for a user who no longer exists, so revoke treats them as gone", async () => {
      databricks.users.delete(ALICE_ID);

      await expect(identifyById(ALICE_ID)).resolves.toBeNull();
    });

    // The lookup that rolls back a failed grant says "grant", and carries the
    // recorded userId just as a revoke's does.
    it.each(["revoke", "grant"] as const)(
      "finds a user who no longer passes domain verification, since P0 already granted to them, when the call says %s",
      async (operation) => {
        databricks.users.set(ALICE_ID, {
          id: ALICE_ID,
          userName: "alice@evil.io",
        });

        await expect(identifyById(ALICE_ID, ALICE, operation)).resolves.toBe(
          ALICE_ID
        );
        expect(domainWarnings()).toBe(0);
      }
    );

    it("rejects a recorded ID that isn't numeric before calling Databricks", async () => {
      await expect(identifyById("1/../2")).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  it("fails naming both users when two match", async () => {
    databricks.users.set(ALICE_ID, {
      id: ALICE_ID,
      userName: "alice.a@contoso.com",
      emails: [{ value: ALICE }],
    });
    databricks.users.set("4444444444444444", {
      id: "4444444444444444",
      userName: "alice.b@contoso.com",
      emails: [{ value: ALICE }],
    });

    await expect(
      admin().identifyUser({
        userBody: { email: ALICE },
        context: workspaceContext(),
      })
    ).rejects.toMatchObject({
      data: {
        type: "validation_error",
        message: expect.stringMatching(
          /alice\.a@contoso\.com.*alice\.b@contoso\.com/
        ),
      },
    });
  });

  it("never creates a missing user", async () => {
    await expect(
      admin().provisionUser({
        userBody: { email: "carol@example.com" },
        context: workspaceContext(),
      })
    ).rejects.toMatchObject({
      data: {
        type: "object_not_found",
        message:
          "No Databricks user `carol@example.com`. Users must already exist.",
      },
    });
    expect(writes()).toEqual([]);
  });

  it("never deletes a user", async () => {
    await admin().deleteUser({
      userId: ALICE_ID,
      userBody: recordedBody(),
      context: workspaceContext({ operation: "revoke" }),
    });

    expect(writes()).toEqual([]);
    expect(databricks.users.has(ALICE_ID)).toBe(true);
  });
});

describe("listers", () => {
  // P0 lists workspaces from its installed items, which needs no account
  // admin.
  it("has no workspaces query", async () => {
    const workspaces = { type: "workspaces", context: accountContext() };

    expect(() => spec.listerQuery(workspaces)).toThrow();
    // @ts-expect-error the query is gone: the parser must refuse it
    await expect(list(workspaces)).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    [undefined, "none"],
    [["USER"], "USER"],
    [["ADMIN"], "ADMIN"],
    [["USER", "ADMIN"], "ADMIN"],
  ])("reports the workspace assignment %j as %s", async (permissions, key) => {
    if (permissions) databricks.assignments.set(ALICE_ID, permissions);

    const [item] = await list(workspaceQuery());
    expect(item?.key).toBe(key);
  });

  it("reads the workspace assignment from the workspace-level API, after binding", async () => {
    await list(workspaceQuery());

    expect(routes()).toEqual([
      bindingRoute,
      `GET ${PROXY_USERS}/${ALICE_ID}`,
      `GET ${ASSIGNMENTS}`,
    ]);
    expect(callUrls().every((url) => url.startsWith(WORKSPACE_URL))).toBe(true);
  });

  it("reports whether the user is account admin when no workspace is given", async () => {
    const query: ListerQuery = {
      type: "priorAssignment",
      context: accountContext(),
      userId: ALICE_ID,
    };

    await expect(list(query)).resolves.toEqual([
      { key: "none", value: "Not an account admin" },
    ]);

    databricks.users.get(ALICE_ID)!.roles = [{ value: "account_admin" }];
    await expect(list(query)).resolves.toEqual([
      { key: "ADMIN", value: "Account admin" },
    ]);
  });

  it("fails for an ID that isn't a user", async () => {
    await expect(
      list({
        type: "priorAssignment",
        context: accountContext(),
        userId: GROUP_ID,
      })
    ).rejects.toMatchObject({ data: { type: "object_not_found" } });
  });
});
