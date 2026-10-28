import { createLogger } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ACCOUNTS_URL,
  ACCOUNT_ID,
  APPLICATION_ID,
  METASTORE_ASSIGNMENT,
  METASTORE_ID,
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
import { DOMAIN_PATTERN_ENV } from "../../../domain.ts";
import { connectorRouter } from "../../../router.ts";
import {
  type Policy,
  type RequestGrant,
  type UserBody,
  spec,
} from "../definition.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);
vi.mock("@p0security/connector-core", async (importOriginal) =>
  (await import("../../../__tests__/logs.ts")).recordingLoggerModule(
    importOriginal
  )
);

resetBetweenTests();

/** Databricks users. A user's Unity Catalog principal is their username, an email. */
const ALICE = { userName: "alice@example.com" };
const BOB = { userName: "bob@example.com" };

const UC_PERMISSIONS = "/api/2.1/unity-catalog/permissions/";
const ACCOUNT_WORKSPACES = `/api/2.0/accounts/${ACCOUNT_ID}/workspaces`;

const unknownUserMessage = (email: string) =>
  `No Databricks user \`${email}\`. P0 grants Unity Catalog privileges only to the Databricks user whose username is this email. Ask a Databricks admin to add that user, then request again.`;

type DatabricksError = { status: number; errorCode: string };

/**
 * An in-memory Databricks workspace: the principals its metastore knows,
 * Unity Catalog direct grants and list APIs, and the workspace's metastore
 * assignment, which binding reads. It serves no account API.
 */
const newFakeDatabricks = () => {
  const state = {
    /** The principals the metastore knows. A change naming another fails. */
    principals: new Set([ALICE.userName, BOB.userName]),
    /** The status a change naming an unknown principal fails with. */
    unknownPrincipalStatus: 404,
    /**
     * Whether a read naming an unknown principal fails too. By default it
     * returns no grants, as a filter that matches nothing would.
     */
    unknownPrincipalFailsReads: false,
    /** The call after which the metastore forgets every principal, if any. */
    forgetsPrincipalsAfter: null as "GET" | "PATCH" | null,
    /** `<type>/<fullName>` → principal → privileges */
    grants: new Map<string, Map<string, Set<string>>>(),
    /** `<type>/<fullName>` → the error every permissions call on it returns */
    errors: new Map<string, DatabricksError>(),
    /** Securables whose PATCH succeeds but changes nothing. */
    ignoresPatches: new Set<string>(),
    /** Securables dropped right after their next PATCH succeeds. */
    dropsAfterPatch: new Set<string>(),
    lists: {} as Record<string, unknown[]>,
    /** Whether `WORKSPACE_URL` still serves the workspace. */
    workspaceUp: true,
    /** What current-metastore-assignment answers on `WORKSPACE_URL`. */
    binding: bindingResponse() as unknown,
  };

  const grantsOn = (securable: string) => {
    const existing = state.grants.get(securable);
    if (existing) return existing;
    const created = new Map<string, Set<string>>();
    state.grants.set(securable, created);
    return created;
  };

  const held = (securable: string, principal: string) => [
    ...(grantsOn(securable).get(principal) ?? []),
  ];

  const grant = (securable: string, principal: string, privileges: string[]) =>
    grantsOn(securable).set(
      principal,
      new Set([...held(securable, principal), ...privileges])
    );

  const unknownPrincipal = (principal: string) =>
    jsonResponse(
      {
        error_code: "PRINCIPAL_DOES_NOT_EXIST",
        message: `Could not find principal with name ${principal}`,
      },
      { status: state.unknownPrincipalStatus }
    );

  const permissions = (url: URL, init: RequestInit) => {
    const securable = decodeURIComponent(
      url.pathname.slice(UC_PERMISSIONS.length)
    );
    const error = state.errors.get(securable);
    if (error) {
      return jsonResponse(
        { error_code: error.errorCode, message: `${error.errorCode} test` },
        { status: error.status }
      );
    }
    if (init.method === "PATCH") {
      const { changes } = JSON.parse(init.body as string) as {
        changes: { principal: string; add?: string[]; remove?: string[] }[];
      };
      const unknown = changes.find(
        ({ principal }) => !state.principals.has(principal)
      );
      if (unknown) return unknownPrincipal(unknown.principal);
      if (state.forgetsPrincipalsAfter === "PATCH") state.principals.clear();
      if (!state.ignoresPatches.has(securable)) {
        for (const { principal, add = [], remove = [] } of changes) {
          const next = new Set([...held(securable, principal), ...add]);
          for (const privilege of remove) next.delete(privilege);
          grantsOn(securable).set(principal, next);
        }
      }
      if (state.dropsAfterPatch.has(securable)) {
        state.errors.set(securable, {
          status: 404,
          errorCode: "TABLE_DOES_NOT_EXIST",
        });
      }
      return jsonResponse({});
    }
    const principal = url.searchParams.get("principal");
    if (
      principal !== null &&
      !state.principals.has(principal) &&
      state.unknownPrincipalFailsReads
    ) {
      return unknownPrincipal(principal);
    }
    if (state.forgetsPrincipalsAfter === "GET") state.principals.clear();
    return jsonResponse({
      privilege_assignments: [...grantsOn(securable)]
        .filter(([, privileges]) => privileges.size)
        .map(([principal, privileges]) => ({
          principal,
          privileges: [...privileges],
        })),
    });
  };

  const handler = (url: string, init: RequestInit) => {
    seen.push(url);
    const parsed = new URL(url);
    const { origin, pathname, searchParams } = parsed;
    // A deleted workspace's URL serves nothing, so a call to it never connects.
    if (
      origin !== ACCOUNTS_URL &&
      !(origin === WORKSPACE_URL && state.workspaceUp)
    ) {
      throw new TypeError("fetch failed");
    }
    // Only the workspace serves anything: `privilege` calls no account API
    // but the token endpoint, which `stubFetch` answers.
    if (origin === WORKSPACE_URL) {
      if (isBinding(url)) return state.binding;
      if (pathname.startsWith(UC_PERMISSIONS)) {
        return permissions(parsed, init);
      }
      const list = state.lists[`${pathname}?${searchParams.toString()}`];
      if (list) return list.shift();
    }
    return jsonResponse({ error_code: "NOT_FOUND" }, { status: 404 });
  };

  return { state, handler, grant, held };
};

let fake: ReturnType<typeof newFakeDatabricks>;
let fetchMock: ReturnType<typeof stubFetch>;
/** Every URL this test asked the fake for. `mockClear` never clears it. */
let seen: string[] = [];

const caller = () =>
  connectorRouter.createCaller({ logger: createLogger() }).databricks.accesses
    .privilege;

type Operation = "grant" | "revoke";

const context = (
  requestGrants: RequestGrant[] = [],
  operation: Operation = "grant"
) => ({
  ...accountContext(),
  workspaceId: WORKSPACE_ID,
  workspaceUrl: WORKSPACE_URL,
  requestGrants,
  operation,
});

const policy = (
  securableType: Policy["securableType"],
  fullName: string,
  privilege: Policy["privilege"]
): Policy => ({ securableType, fullName, privilege });

/** What one request for `SELECT` on a table adds: the table grant plus the parent `USE`s. */
const selectOnTable = (table: string): Policy[] => [
  policy("catalog", "main", "USE_CATALOG"),
  policy("schema", "main.sales", "USE_SCHEMA"),
  policy("table", `main.sales.${table}`, "SELECT"),
];

/**
 * One `setPoliciesForUser` call. Named, because both lists have the same
 * shape, and swapping them turns a grant into a revoke.
 */
type PoliciesCall = {
  /** The union of every open request's grants, as the control plane sends it. */
  policies: Policy[];
  /** The grants this request added, or is adding. */
  requestGrants: RequestGrant[];
  userId?: string;
  /** Defaults to the body P0 sends once it recorded the `userName` at stage. */
  userBody?: UserBody;
};

/** The user body P0 sends with a user ID, carrying the `userName` it recorded at stage. */
const recordedBody = (userName: string): UserBody => ({
  email: userName,
  userName,
});

const setPolicies = (
  operation: Operation,
  {
    policies,
    requestGrants,
    userId = ALICE.userName,
    userBody = recordedBody(userId),
  }: PoliciesCall
) =>
  caller().setPoliciesForUser({
    userId,
    userBody,
    policies,
    context: context(requestGrants, operation),
  });

/** Grants `requestGrants`. `policies` is the union of every open request's grants. */
const grant = (call: PoliciesCall) => setPolicies("grant", call);

/** Revokes `requestGrants`. `policies` is the union of the open siblings' grants. */
const revoke = (call: PoliciesCall) => setPolicies("revoke", call);

const patches = () =>
  fetchCalls(fetchMock)
    .filter((call) => call.init.method === "PATCH")
    .map((call) => ({
      securable: decodeURIComponent(
        new URL(call.url).pathname.slice(UC_PERMISSIONS.length)
      ),
      ...(JSON.parse(call.init.body ?? "{}") as {
        changes: unknown[];
      }),
    }));

const databricksCalls = () =>
  fetchCalls(fetchMock).filter((call) => !isTokenExchange(call));

const bindings = () => databricksCalls().filter((call) => isBinding(call.url));

/** Calls to the account workspaces API, which the connector no longer makes. */
const accountWorkspaceCalls = () =>
  fetchCalls(fetchMock).filter((call) =>
    call.url.startsWith(`${ACCOUNTS_URL}${ACCOUNT_WORKSPACES}`)
  );

/** Calls that went to a workspace rather than the account console. */
const workspaceCalls = () =>
  databricksCalls().filter((call) => !call.url.startsWith(ACCOUNTS_URL));

beforeEach(() => {
  vi.stubEnv(DOMAIN_PATTERN_ENV, "example\\.com");
  seen = [];
  fake = newFakeDatabricks();
  fetchMock = stubFetch(fake.handler);
  warn.mockClear();
});

// `privilege` never looks a user up and calls no account API but the token
// endpoint, which `stubFetch` answers before the fake sees it. Checked after
// every test in this file.
afterEach(() => {
  expect(seen.filter((url) => url.includes("/scim/v2/"))).toEqual([]);
  expect(seen.filter((url) => url.startsWith(ACCOUNTS_URL))).toEqual([]);
});

const identify = (
  userBody: { email: string; userName?: string },
  operation: Operation = "grant"
) => caller().identifyUser({ userBody, context: context([], operation) });

const domainRefusal = (email: string) => ({
  message: `Domain verification refused ${email}: DOMAIN_PATTERN on the connector must match the whole domain after the @.`,
  data: { type: "validation_error" },
});

describe("privilege schema", () => {
  it.each(["MANAGE", "ALL_PRIVILEGES", "ALL PRIVILEGES", "OWNERSHIP"])(
    "never parses %s as a privilege",
    (privilege) => {
      expect(() =>
        spec.policy({ securableType: "catalog", fullName: "main", privilege })
      ).toThrow();
    }
  );

  it("never parses EXTERNAL_USE_SCHEMA as a privilege", () => {
    expect(() =>
      spec.policy({
        securableType: "schema",
        fullName: "main.sales",
        privilege: "EXTERNAL_USE_SCHEMA",
      })
    ).toThrow();
  });

  it("parses a policy naming a privilege P0 no longer grants, which a sibling's stored grant can", () => {
    const retired = policy("catalog", "main", "CREATE_CONNECTION");
    expect(spec.policy(retired)).toEqual(retired);
    expect(() => spec.policy(policy("catalog", "main", "select"))).toThrow();
  });

  it("rejects a full name that doesn't match the securable type", () => {
    expect(() =>
      spec.policy(policy("table", "main.sales", "SELECT"))
    ).toThrow();
    expect(() =>
      spec.policy(policy("schema", "main..", "USE_SCHEMA"))
    ).toThrow();
  });
});

describe("validation", () => {
  it("refuses a user outside DOMAIN_PATTERN before calling Databricks, saying why", async () => {
    await expect(
      grant({
        policies: selectOnTable("orders"),
        requestGrants: selectOnTable("orders"),
        userId: "mallory@evil.example",
      })
    ).rejects.toMatchObject(domainRefusal("mallory@evil.example"));
    await expect(
      identify({ email: "mallory@evil.example" })
    ).rejects.toMatchObject(domainRefusal("mallory@evil.example"));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses every user when DOMAIN_PATTERN is unset, saying domain verification isn't configured", async () => {
    vi.stubEnv(DOMAIN_PATTERN_ENV, "");

    await expect(
      grant({
        policies: selectOnTable("orders"),
        requestGrants: selectOnTable("orders"),
      })
    ).rejects.toMatchObject({
      message: expect.stringMatching(
        /^Domain verification is not configured: DOMAIN_PATTERN is not set/
      ),
      data: { type: "validation_error" },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("checks the email itself, the principal P0 grants to, with no lookup", async () => {
    vi.stubEnv(DOMAIN_PATTERN_ENV, "contoso\\.com");

    await expect(identify({ email: "dave@example.com" })).rejects.toMatchObject(
      domainRefusal("dave@example.com")
    );
    await expect(identify({ email: "dave@contoso.com" })).resolves.toBe(
      "dave@contoso.com"
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("domain verification on revoke", () => {
  const orders = selectOnTable("orders");

  beforeEach(async () => {
    await grant({ policies: orders, requestGrants: orders });
  });

  const narrowPattern = () => vi.stubEnv(DOMAIN_PATTERN_ENV, "other\\.com");

  it.each([
    ["the pattern narrows", narrowPattern],
    ["the pattern is unset", () => vi.stubEnv(DOMAIN_PATTERN_ENV, undefined)],
    ["the pattern is invalid", () => vi.stubEnv(DOMAIN_PATTERN_ENV, "(other")],
  ])(
    "revokes a user found by recorded identity after %s, warning once",
    async (_, changePattern) => {
      changePattern();

      await expect(
        identify({ email: ALICE.userName, userName: ALICE.userName }, "revoke")
      ).resolves.toBe(ALICE.userName);
      // The lookup by recorded identity checks nothing and logs nothing.
      expect(domainWarnings()).toBe(0);
      await expect(
        revoke({ policies: [], requestGrants: orders })
      ).resolves.toBeNull();
      expect(domainWarnings()).toBe(1);

      for (const securable of [
        "catalog/main",
        "schema/main.sales",
        "table/main.sales.orders",
      ]) {
        expect(fake.held(securable, ALICE.userName)).toEqual([]);
      }
    }
  );

  it("still refuses an email-only lookup once the user no longer passes", async () => {
    narrowPattern();

    await expect(identify({ email: ALICE.userName })).rejects.toMatchObject(
      domainRefusal(ALICE.userName)
    );
  });

  // The framework runs the body check before `setPoliciesForUser` and
  // `deleteUser` too. A body without the recorded `userName` is checked by
  // its email, and on a revoke that check only warns.
  describe("a body carrying only the email", () => {
    const emailOnly = { email: ALICE.userName };

    it("revokes, warning rather than refusing", async () => {
      narrowPattern();

      await expect(
        revoke({ policies: [], requestGrants: orders, userBody: emailOnly })
      ).resolves.toBeNull();
      // One from the body check, one from the revoke itself.
      expect(domainWarnings()).toBe(2);
      expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([]);
    });

    it("lets deleteUser through on a revoke", async () => {
      narrowPattern();
      fetchMock.mockClear();

      await expect(
        caller().deleteUser({
          userId: ALICE.userName,
          userBody: emailOnly,
          context: context([], "revoke"),
        })
      ).resolves.toBeNull();
      expect(domainWarnings()).toBe(1);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("still refuses a grant", async () => {
      narrowPattern();
      fetchMock.mockClear();

      await expect(
        grant({
          policies: selectOnTable("customers"),
          requestGrants: selectOnTable("customers"),
          userBody: emailOnly,
        })
      ).rejects.toMatchObject(domainRefusal(ALICE.userName));
      expect(patches()).toEqual([]);
    });
  });

  it("still refuses a grant once the user no longer passes, even found by recorded identity", async () => {
    narrowPattern();
    fetchMock.mockClear();

    // The lookup by recorded identity only finds the user...
    await expect(
      caller().provisionUser({
        userBody: { email: ALICE.userName, userName: ALICE.userName },
        context: context(),
      })
    ).resolves.toBe(ALICE.userName);
    // ...and the grant itself is refused, before anything is written.
    await expect(
      grant({
        policies: selectOnTable("customers"),
        requestGrants: selectOnTable("customers"),
      })
    ).rejects.toMatchObject(domainRefusal(ALICE.userName));
    expect(patches()).toEqual([]);
  });

  describe("a revoke for a user who no longer passes adds nothing", () => {
    const customers = selectOnTable("customers");

    beforeEach(async () => {
      await grant({
        policies: [...orders, ...customers],
        requestGrants: customers,
      });
      // Someone removed the USE_SCHEMA both requests share.
      fake.state.grants.get("schema/main.sales")?.delete(ALICE.userName);
      fetchMock.mockClear();
    });

    it("re-adds the shared USE_SCHEMA for a user who still passes", async () => {
      await revoke({ policies: customers, requestGrants: orders });

      expect(fake.held("schema/main.sales", ALICE.userName)).toEqual([
        "USE_SCHEMA",
      ]);
    });

    it("only removes for a user who no longer passes", async () => {
      narrowPattern();

      await expect(
        revoke({ policies: customers, requestGrants: orders })
      ).resolves.toBeNull();

      expect(patches()).toEqual([
        {
          securable: "table/main.sales.orders",
          changes: [{ principal: ALICE.userName, remove: ["SELECT"] }],
        },
      ]);
      expect(fake.held("schema/main.sales", ALICE.userName)).toEqual([]);
    });
  });
});

// The framework runs `userIsNamespacedByBody` before `setPoliciesForUser` and
// `deleteUser`. Once a request has staged, P0 sends the requestor's current
// email with the `userName` it recorded, and the check passes on that, even
// when the email has since left DOMAIN_PATTERN.
describe("the framework's body check, on the userBody P0 sends after stage", () => {
  const orders = selectOnTable("orders");
  const sentBody: UserBody = {
    email: "alice@elsewhere.example",
    userName: ALICE.userName,
  };

  it("passes before setPoliciesForUser on a grant", async () => {
    await expect(
      grant({ policies: orders, requestGrants: orders, userBody: sentBody })
    ).resolves.toBeNull();
    expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([
      "SELECT",
    ]);
    expect(domainWarnings()).toBe(0);
  });

  it("passes before setPoliciesForUser on a revoke", async () => {
    await grant({ policies: orders, requestGrants: orders });

    await expect(
      revoke({ policies: [], requestGrants: orders, userBody: sentBody })
    ).resolves.toBeNull();
    expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([]);
    expect(domainWarnings()).toBe(0);
  });

  it.each(["grant", "revoke"] as const)(
    "passes before deleteUser when the call says %s",
    async (operation) => {
      await expect(
        caller().deleteUser({
          userId: ALICE.userName,
          userBody: sentBody,
          context: context([], operation),
        })
      ).resolves.toBeNull();
      expect(domainWarnings()).toBe(0);
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );
});

describe("the operation the context names", () => {
  const orders = selectOnTable("orders");
  const customers = selectOnTable("customers");

  beforeEach(async () => {
    await grant({ policies: orders, requestGrants: orders });
    fetchMock.mockClear();
  });

  // When a grant fails partway, the control plane rolls it back with the
  // open siblings' policies, and those calls still say "grant".
  describe("a call labeled grant that removes something, as a rollback's does", () => {
    const removesOrdersSelect = {
      securable: "table/main.sales.orders",
      changes: [{ principal: ALICE.userName, remove: ["SELECT"] }],
    };

    beforeEach(async () => {
      // `customers` is an open sibling request in the same schema.
      await grant({
        policies: [...orders, ...customers],
        requestGrants: customers,
      });
      fetchMock.mockClear();
      warn.mockClear();
    });

    it("warns once that it takes the call for a failed grant's rollback, naming what it removes", async () => {
      await expect(
        grant({ policies: customers, requestGrants: orders })
      ).resolves.toBeNull();

      expect(warn.mock.calls).toEqual([
        [
          { removed: "SELECT@table:main.sales.orders" },
          "call says grant but removes grants; treating it as the rollback of a failed grant",
        ],
      ]);
    });

    it("revokes only what no sibling still needs", async () => {
      await expect(
        grant({ policies: customers, requestGrants: orders })
      ).resolves.toBeNull();

      expect(patches()).toEqual([removesOrdersSelect]);
      expect(fake.held("schema/main.sales", ALICE.userName)).toEqual([
        "USE_SCHEMA",
      ]);
      expect(fake.held("table/main.sales.customers", ALICE.userName)).toEqual([
        "SELECT",
      ]);
    });

    it.each([
      ["the pattern narrows", "other\\.com"],
      ["the pattern is unset", undefined],
      ["the pattern is invalid", "(other"],
    ])("isn't refused after %s, and adds nothing back", async (_, pattern) => {
      vi.stubEnv(DOMAIN_PATTERN_ENV, pattern);
      // Someone removed the USE_SCHEMA both requests share.
      fake.state.grants.get("schema/main.sales")?.delete(ALICE.userName);

      await expect(
        grant({ policies: customers, requestGrants: orders })
      ).resolves.toBeNull();

      expect(patches()).toEqual([removesOrdersSelect]);
      expect(domainWarnings()).toBe(1);
    });

    it("counts a principal Databricks no longer knows as revoked", async () => {
      fake.state.principals.delete(ALICE.userName);

      await expect(
        grant({ policies: customers, requestGrants: orders })
      ).resolves.toBeNull();

      expect(patches()).toEqual([removesOrdersSelect]);
      expect(warn).toHaveBeenCalledWith(
        "user not found on revoke; treating as revoked"
      );
    });

    it("counts a dropped securable as revoked", async () => {
      fake.state.errors.set("table/main.sales.orders", {
        status: 404,
        errorCode: "TABLE_DOES_NOT_EXIST",
      });

      await expect(
        grant({ policies: customers, requestGrants: orders })
      ).resolves.toBeNull();

      expect(warn).toHaveBeenCalledWith(
        { securable: { type: "table", fullName: "main.sales.orders" } },
        "securable not found on revoke; treating as revoked"
      );
      expect(
        patches().filter((p) => JSON.stringify(p).includes('"add"'))
      ).toEqual([]);
      expect(fake.held("schema/main.sales", ALICE.userName)).toEqual([
        "USE_SCHEMA",
      ]);
    });
  });

  // The most common rollback: no open sibling, so no policies at all.
  it("takes a call labeled grant with no policies for a revoke, removing every grant leaves first, after the pattern narrows", async () => {
    vi.stubEnv(DOMAIN_PATTERN_ENV, "other\\.com");

    await expect(
      grant({ policies: [], requestGrants: orders })
    ).resolves.toBeNull();

    expect(patches()).toEqual([
      {
        securable: "table/main.sales.orders",
        changes: [{ principal: ALICE.userName, remove: ["SELECT"] }],
      },
      {
        securable: "schema/main.sales",
        changes: [{ principal: ALICE.userName, remove: ["USE_SCHEMA"] }],
      },
      {
        securable: "catalog/main",
        changes: [{ principal: ALICE.userName, remove: ["USE_CATALOG"] }],
      },
    ]);
    for (const securable of [
      "catalog/main",
      "schema/main.sales",
      "table/main.sales.orders",
    ]) {
      expect(fake.held(securable, ALICE.userName)).toEqual([]);
    }
    expect(domainWarnings()).toBe(1);
  });

  it("warns about neither a grant nor a revoke whose label agrees", async () => {
    await grant({
      policies: [...orders, ...customers],
      requestGrants: customers,
    });
    await revoke({ policies: customers, requestGrants: orders });

    expect(warn).not.toHaveBeenCalled();
  });

  it("refuses a grant that adds nothing for a user who no longer passes, before calling Databricks", async () => {
    vi.stubEnv(DOMAIN_PATTERN_ENV, "other\\.com");

    // Alice already holds everything `orders` grants. Refusing anyway is what
    // stops a user outside the pattern keeping access by asking again.
    await expect(
      grant({ policies: orders, requestGrants: orders })
    ).rejects.toMatchObject(domainRefusal(ALICE.userName));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // An identical sibling request, such as a renewal before the first one
  // expires, still needs every grant, so the revoke's policies cover all of
  // its requestGrants and it removes nothing.
  describe("a revoke an open sibling request fully covers", () => {
    it.each([
      ["the pattern narrows", "other\\.com"],
      ["the pattern is unset", undefined],
      ["the pattern is invalid", "(other"],
    ])("resolves after %s, and writes nothing", async (_, pattern) => {
      vi.stubEnv(DOMAIN_PATTERN_ENV, pattern);

      await expect(
        revoke({ policies: orders, requestGrants: orders })
      ).resolves.toBeNull();

      expect(patches()).toEqual([]);
      expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([
        "SELECT",
      ]);
      expect(domainWarnings()).toBe(1);
    });

    it("resolves when one of its securables has been dropped", async () => {
      fake.state.errors.set("table/main.sales.orders", {
        status: 404,
        errorCode: "TABLE_DOES_NOT_EXIST",
      });

      await expect(
        revoke({ policies: orders, requestGrants: orders })
      ).resolves.toBeNull();
      expect(patches()).toEqual([]);
    });
  });
});

describe("users", () => {
  it("identifies the requestor by their email, with no call", async () => {
    await expect(identify({ email: ALICE.userName })).resolves.toBe(
      ALICE.userName
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("provisions the requestor by their email, with no call and never creating a user", async () => {
    await expect(
      caller().provisionUser({
        userBody: { email: "carol@example.com" },
        context: context(),
      })
    ).resolves.toBe("carol@example.com");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  describe("by the userName P0 recorded", () => {
    it.each(["identifyUser", "provisionUser"] as const)(
      "%s returns it, ignoring an email that has since changed, with no call",
      async (procedure) => {
        await expect(
          caller()[procedure]({
            userBody: {
              email: "alice.new@example.com",
              userName: ALICE.userName,
            },
            context: context([], "revoke"),
          })
        ).resolves.toBe(ALICE.userName);
        expect(fetchMock).not.toHaveBeenCalled();
      }
    );

    // The lookup that rolls back a failed grant says "grant", and carries the
    // recorded userName just as a revoke's does.
    it.each(["revoke", "grant"] as const)(
      "returns one that no longer passes domain verification, since P0 already granted to it, when the call says %s",
      async (operation) => {
        await expect(
          identify(
            { email: ALICE.userName, userName: "alice@evil.example" },
            operation
          )
        ).resolves.toBe("alice@evil.example");
        expect(domainWarnings()).toBe(0);
      }
    );

    it("rejects a recorded userName that isn't an email before calling Databricks", async () => {
      await expect(
        identify({ email: ALICE.userName, userName: "data-team" })
      ).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  it("never deletes a user", async () => {
    await expect(
      caller().deleteUser({
        userId: ALICE.userName,
        userBody: recordedBody(ALICE.userName),
        context: context([], "revoke"),
      })
    ).resolves.toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("workspace", () => {
  it("binds the workspace, then sends every Unity Catalog call to its URL", async () => {
    await grant({
      policies: selectOnTable("orders"),
      requestGrants: selectOnTable("orders"),
    });

    const calls = workspaceCalls();
    expect(calls[0]?.url).toBe(`${WORKSPACE_URL}${METASTORE_ASSIGNMENT}`);
    const ucCalls = calls.slice(1);
    expect(ucCalls.length).toBeGreaterThan(0);
    expect(
      ucCalls.every((call) =>
        call.url.startsWith(`${WORKSPACE_URL}/api/2.1/unity-catalog/`)
      )
    ).toBe(true);
    expect(accountWorkspaceCalls()).toEqual([]);
    // Nothing looks the user or the connector's own principal up.
    expect(calls.some((call) => call.url.includes("/scim/v2/"))).toBe(false);
  });

  it("refuses a URL that answers for another workspace, before any Unity Catalog call", async () => {
    fake.state.binding = bindingResponse("42");

    await expect(
      grant({
        policies: selectOnTable("orders"),
        requestGrants: selectOnTable("orders"),
      })
    ).rejects.toMatchObject({
      message: `Databricks workspace URL ${WORKSPACE_URL} belongs to workspace 42, not ${WORKSPACE_ID}. Check the URL saved for workspace ${WORKSPACE_ID} in P0.`,
      data: { type: "validation_error" },
    });
    expect(workspaceCalls().map((call) => call.url)).toEqual([
      `${WORKSPACE_URL}${METASTORE_ASSIGNMENT}`,
    ]);
  });

  // A URL always serves the same workspace, so grants and revokes share one
  // binding per Lambda instance. Each still compares the requested ID.
  it("binds each URL once, for grants and revokes alike", async () => {
    const orders = selectOnTable("orders");

    await grant({ policies: orders, requestGrants: orders });
    await grant({ policies: orders, requestGrants: orders });
    await revoke({ policies: orders, requestGrants: orders });
    await revoke({ policies: [], requestGrants: orders });

    expect(bindings()).toHaveLength(1);
  });

  it.each([
    ["off the Databricks domains", "https://evil.example"],
    ["with a path", `${WORKSPACE_URL}/api`],
  ])(
    "refuses a workspace URL %s before calling anything",
    async (_, workspaceUrl) => {
      await expect(
        caller().setPoliciesForUser({
          userId: ALICE.userName,
          userBody: recordedBody(ALICE.userName),
          policies: selectOnTable("orders"),
          context: { ...context(selectOnTable("orders")), workspaceUrl },
        })
      ).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it("refuses a context without a workspace URL before calling anything", async () => {
    const { workspaceUrl: _, ...withoutUrl } = context(selectOnTable("orders"));

    await expect(
      caller().setPoliciesForUser({
        userId: ALICE.userName,
        userBody: recordedBody(ALICE.userName),
        policies: selectOnTable("orders"),
        // @ts-expect-error the URL is required: the parser must refuse this
        context: withoutUrl,
      })
    ).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

// The grants live on the metastore, so they outlive the workspace P0
// recorded at stage, and still work from its other workspaces.
describe("a revoke whose workspace can't be bound", () => {
  const orders = selectOnTable("orders");
  const customers = selectOnTable("customers");
  const ordersKeys =
    "USE_CATALOG@catalog:main, USE_SCHEMA@schema:main.sales, SELECT@table:main.sales.orders";

  const unreachableMessage = (grants: string) =>
    `P0 can't reach Databricks workspace ${WORKSPACE_ID} at ${WORKSPACE_URL} to revoke. If the workspace was deleted, Unity Catalog grants outlive it, so remove these from ${ALICE.userName} by hand in another workspace on the same metastore: ${grants}`;

  const failsNamingOrders = (type: string) => ({
    message: unreachableMessage(ordersKeys),
    data: {
      type,
      payload: {
        workspaceId: WORKSPACE_ID,
        workspaceUrl: WORKSPACE_URL,
        principal: ALICE.userName,
        grants: ordersKeys,
      },
    },
  });

  beforeEach(() => {
    fake.grant("catalog/main", ALICE.userName, ["USE_CATALOG"]);
    fake.grant("schema/main.sales", ALICE.userName, ["USE_SCHEMA"]);
    fake.grant("table/main.sales.orders", ALICE.userName, ["SELECT"]);
  });

  describe("because the workspace was deleted", () => {
    beforeEach(() => {
      fake.state.workspaceUp = false;
    });

    it("fails naming each grant still to remove by hand, keeping the binding error's type", async () => {
      const error: unknown = await revoke({
        policies: [],
        requestGrants: orders,
      }).catch((e: unknown) => e);

      expect(error).toMatchObject(failsNamingOrders("upstream_unavailable"));
      expect(error).toHaveProperty(
        "cause.data.message",
        `Databricks GET ${METASTORE_ASSIGNMENT} failed: fetch failed`
      );
      expect(patches()).toEqual([]);
    });

    it("names only the grants no open sibling still needs, on a rollback too", async () => {
      await expect(
        grant({ policies: customers, requestGrants: orders })
      ).rejects.toMatchObject({
        message: unreachableMessage("SELECT@table:main.sales.orders"),
      });
    });

    it("fails a grant with the binding's own error", async () => {
      await expect(
        grant({ policies: orders, requestGrants: orders })
      ).rejects.toMatchObject({
        message: `Databricks GET ${METASTORE_ASSIGNMENT} failed: fetch failed`,
        data: { type: "upstream_unavailable" },
      });
    });

    it("fails a revoke that removes nothing with the binding's own error", async () => {
      await expect(
        revoke({ policies: orders, requestGrants: orders })
      ).rejects.toMatchObject({
        message: `Databricks GET ${METASTORE_ASSIGNMENT} failed: fetch failed`,
      });
    });

    // A binding cached before the deletion still binds, so the revoke's own
    // calls fail instead. It never counts as revoked.
    it("fails closed with the Unity Catalog call's error once the binding is cached", async () => {
      fake.state.workspaceUp = true;
      await grant({ policies: customers, requestGrants: customers });
      fake.state.workspaceUp = false;

      await expect(
        revoke({ policies: [], requestGrants: orders })
      ).rejects.toMatchObject({ data: { type: "upstream_unavailable" } });
      expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([
        "SELECT",
      ]);
    });
  });

  it("names the grants when the URL now answers for another workspace, keeping validation_error", async () => {
    fake.state.binding = bindingResponse("42");

    await expect(
      revoke({ policies: [], requestGrants: orders })
    ).rejects.toMatchObject(failsNamingOrders("validation_error"));
    expect(patches()).toEqual([]);
  });

  it("never asks the account workspaces API", async () => {
    fake.state.workspaceUp = false;

    await expect(
      revoke({ policies: [], requestGrants: orders })
    ).rejects.toThrow();
    expect(accountWorkspaceCalls()).toEqual([]);
  });
});

describe("setPoliciesForUser", () => {
  it("grants each securable's privileges in one PATCH, catalog first, then confirms them", async () => {
    const grants = selectOnTable("orders");

    await grant({ policies: grants, requestGrants: grants });

    expect(patches()).toEqual([
      {
        securable: "catalog/main",
        changes: [{ principal: ALICE.userName, add: ["USE_CATALOG"] }],
      },
      {
        securable: "schema/main.sales",
        changes: [{ principal: ALICE.userName, add: ["USE_SCHEMA"] }],
      },
      {
        securable: "table/main.sales.orders",
        changes: [{ principal: ALICE.userName, add: ["SELECT"] }],
      },
    ]);
    // Each securable is read before the add (to skip what's already held)
    // and after it (to confirm).
    const reads = databricksCalls().filter(
      (call) => call.init.method === "GET" && call.url.includes(UC_PERMISSIONS)
    );
    expect(reads).toHaveLength(6);
    expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([
      "SELECT",
    ]);
  });

  it("revokes only requestGrants − policies, keeping a USE_SCHEMA a sibling request still needs", async () => {
    const orders = selectOnTable("orders");
    const customers = selectOnTable("customers");
    await grant({ policies: orders, requestGrants: orders });
    await grant({
      policies: [...orders, ...customers],
      requestGrants: customers,
    });
    fetchMock.mockClear();

    // Revoke `orders`; `customers` is still open in the same schema.
    await revoke({ policies: customers, requestGrants: orders });

    expect(
      patches().filter((p) => JSON.stringify(p).includes("remove"))
    ).toEqual([
      {
        securable: "table/main.sales.orders",
        changes: [{ principal: ALICE.userName, remove: ["SELECT"] }],
      },
    ]);
    expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([]);
    expect(fake.held("schema/main.sales", ALICE.userName)).toEqual([
      "USE_SCHEMA",
    ]);
    expect(fake.held("catalog/main", ALICE.userName)).toEqual(["USE_CATALOG"]);

    // Revoke `customers`, the last open request: everything goes, leaves first.
    fetchMock.mockClear();
    await revoke({ policies: [], requestGrants: customers });

    expect(patches().map((p) => p.securable)).toEqual([
      "table/main.sales.customers",
      "schema/main.sales",
      "catalog/main",
    ]);
    expect(fake.held("schema/main.sales", ALICE.userName)).toEqual([]);
    expect(fake.held("catalog/main", ALICE.userName)).toEqual([]);
  });

  it("grants only this request's grants, not the sibling requests' in policies", async () => {
    const orders = selectOnTable("orders");
    const customers = selectOnTable("customers");

    await grant({
      policies: [...orders, ...customers],
      requestGrants: customers,
    });

    expect(patches().map((p) => p.securable)).toEqual([
      "catalog/main",
      "schema/main.sales",
      "table/main.sales.customers",
    ]);
    expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([]);
  });

  it("writes nothing for a sibling request's securables on revoke, and only reads back what it touched", async () => {
    const orders = selectOnTable("orders");
    const invoices = [policy("table", "finance.ledger.invoices", "SELECT")];
    await grant({
      policies: [...orders, ...invoices],
      requestGrants: invoices,
    });
    await grant({ policies: [...orders, ...invoices], requestGrants: orders });
    fetchMock.mockClear();

    await revoke({ policies: invoices, requestGrants: orders });

    const touched = databricksCalls()
      .filter((call) => call.url.includes(UC_PERMISSIONS))
      .map((call) =>
        decodeURIComponent(
          new URL(call.url).pathname.slice(UC_PERMISSIONS.length)
        )
      );
    expect(touched.some((securable) => securable.includes("finance"))).toBe(
      false
    );
    expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([]);
    expect(fake.held("table/finance.ledger.invoices", ALICE.userName)).toEqual([
      "SELECT",
    ]);
  });

  it("adds only what isn't already held", async () => {
    fake.grant("catalog/main", ALICE.userName, ["USE_CATALOG"]);

    await grant({
      policies: selectOnTable("orders"),
      requestGrants: selectOnTable("orders"),
    });

    expect(patches().map((p) => p.securable)).toEqual([
      "schema/main.sales",
      "table/main.sales.orders",
    ]);
  });

  it("never PATCHes an add on revoke for a grant a sibling request still holds", async () => {
    const orders = selectOnTable("orders");
    const customers = selectOnTable("customers");
    await grant({ policies: orders, requestGrants: orders });
    await grant({
      policies: [...orders, ...customers],
      requestGrants: customers,
    });
    fetchMock.mockClear();

    await revoke({ policies: customers, requestGrants: orders });

    expect(patches()).toEqual([
      {
        securable: "table/main.sales.orders",
        changes: [{ principal: ALICE.userName, remove: ["SELECT"] }],
      },
    ]);
  });

  // A failed grant's rollback runs once and is never retried, so a revoke
  // gives every removal its chance.
  describe("a revoke's calls", () => {
    const orders = selectOnTable("orders");
    const customers = selectOnTable("customers");

    beforeEach(async () => {
      await grant({ policies: orders, requestGrants: orders });
    });

    it("attempts every removal, leaves first, when some fail, then throws the first failure", async () => {
      fake.state.errors.set("table/main.sales.orders", {
        status: 503,
        errorCode: "TEMPORARILY_UNAVAILABLE",
      });
      fake.state.errors.set("schema/main.sales", {
        status: 500,
        errorCode: "INTERNAL_ERROR",
      });
      fetchMock.mockClear();

      await expect(
        revoke({ policies: [], requestGrants: orders })
      ).rejects.toMatchObject({
        data: {
          payload: { status: 503, errorCode: "TEMPORARILY_UNAVAILABLE" },
        },
      });

      expect(patches().map((p) => p.securable)).toEqual([
        "table/main.sales.orders",
        "schema/main.sales",
        "catalog/main",
      ]);
      expect(fake.held("catalog/main", ALICE.userName)).toEqual([]);
    });

    describe("beside an open sibling", () => {
      beforeEach(async () => {
        await grant({
          policies: [...orders, ...customers],
          requestGrants: customers,
        });
        fetchMock.mockClear();
      });

      it("removes this request's grants before it repairs one it shares", async () => {
        // Someone removed the USE_SCHEMA both requests share.
        fake.state.grants.get("schema/main.sales")?.delete(ALICE.userName);

        await revoke({ policies: customers, requestGrants: orders });

        expect(patches()).toEqual([
          {
            securable: "table/main.sales.orders",
            changes: [{ principal: ALICE.userName, remove: ["SELECT"] }],
          },
          {
            securable: "schema/main.sales",
            changes: [{ principal: ALICE.userName, add: ["USE_SCHEMA"] }],
          },
        ]);
      });

      it("still removes this request's grants when a repair fails, then throws", async () => {
        // Reading the USE_SCHEMA both requests share fails.
        fake.state.errors.set("schema/main.sales", {
          status: 503,
          errorCode: "TEMPORARILY_UNAVAILABLE",
        });

        await expect(
          revoke({ policies: customers, requestGrants: orders })
        ).rejects.toMatchObject({
          data: { type: "upstream_unavailable", payload: { status: 503 } },
        });

        expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual(
          []
        );
      });
    });
  });

  it("revokes when the shared parent schema has been dropped", async () => {
    const orders = selectOnTable("orders");
    const customers = selectOnTable("customers");
    await grant({ policies: orders, requestGrants: orders });
    await grant({
      policies: [...orders, ...customers],
      requestGrants: customers,
    });
    for (const securable of [
      "schema/main.sales",
      "table/main.sales.orders",
      "table/main.sales.customers",
    ]) {
      fake.state.errors.set(securable, {
        status: 404,
        errorCode: securable.startsWith("schema")
          ? "SCHEMA_DOES_NOT_EXIST"
          : "TABLE_DOES_NOT_EXIST",
      });
    }
    fetchMock.mockClear();

    // USE_SCHEMA on the dropped schema is shared with `customers`, so it's in
    // policies ∩ requestGrants, and must not fail the revoke.
    await expect(
      revoke({ policies: customers, requestGrants: orders })
    ).resolves.toBeNull();
    expect(
      patches().filter((p) => JSON.stringify(p).includes('"add"'))
    ).toEqual([]);
  });

  it("still fails a grant on a dropped table", async () => {
    fake.state.errors.set("table/main.sales.orders", {
      status: 404,
      errorCode: "TABLE_DOES_NOT_EXIST",
    });

    await expect(
      grant({
        policies: selectOnTable("orders"),
        requestGrants: selectOnTable("orders"),
      })
    ).rejects.toMatchObject({
      data: { payload: { status: 404, errorCode: "TABLE_DOES_NOT_EXIST" } },
    });
  });

  it("revokes even when a sibling request's table has been dropped", async () => {
    const orders = selectOnTable("orders");
    const invoices = [policy("table", "finance.ledger.invoices", "SELECT")];
    await grant({
      policies: [...orders, ...invoices],
      requestGrants: invoices,
    });
    await grant({ policies: [...orders, ...invoices], requestGrants: orders });
    fake.state.errors.set("table/finance.ledger.invoices", {
      status: 404,
      errorCode: "TABLE_DOES_NOT_EXIST",
    });

    await expect(
      revoke({ policies: invoices, requestGrants: orders })
    ).resolves.toBeNull();

    expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([]);
    expect(fake.held("catalog/main", ALICE.userName)).toEqual([]);
  });

  it("revokes a stored grant whose privilege P0 no longer grants", async () => {
    // A privilege since dropped from UC_PRIVILEGES, or one Databricks added.
    const retired = {
      securableType: "catalog",
      fullName: "main",
      privilege: "CREATE_CONNECTION",
    } as const;
    fake.grant("catalog/main", ALICE.userName, ["CREATE_CONNECTION"]);

    await expect(
      revoke({ policies: [], requestGrants: [retired] })
    ).resolves.toBeNull();

    expect(patches()).toEqual([
      {
        securable: "catalog/main",
        changes: [{ principal: ALICE.userName, remove: ["CREATE_CONNECTION"] }],
      },
    ]);
    expect(fake.held("catalog/main", ALICE.userName)).toEqual([]);
  });

  it.each([
    "MANAGE",
    "ALL_PRIVILEGES",
    "ALL PRIVILEGES",
    "OWNERSHIP",
    "EXTERNAL_USE_SCHEMA",
    "EXTERNAL USE SCHEMA",
  ])(
    "refuses the never-grantable %j even in a revoke, before calling Databricks",
    async (privilege) => {
      await expect(
        revoke({
          policies: [],
          requestGrants: [
            { securableType: "catalog", fullName: "main", privilege },
          ],
        })
      ).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it.each(["select", "SELECT; DROP", ""])(
    "rejects the stored privilege %j, which isn't a privilege name, before calling Databricks",
    async (privilege) => {
      await expect(
        revoke({
          policies: [],
          requestGrants: [
            { securableType: "catalog", fullName: "main", privilege },
          ],
        })
      ).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  describe("a privilege P0 no longer grants", () => {
    // A privilege since dropped from UC_PRIVILEGES, or one Databricks added.
    const retired = policy("catalog", "main", "CREATE_CONNECTION");
    const orders = selectOnTable("orders");
    /** An open sibling request that holds the retired privilege. */
    const sibling = [policy("catalog", "main", "USE_CATALOG"), retired];

    beforeEach(async () => {
      await grant({ policies: orders, requestGrants: orders });
      fake.grant("catalog/main", ALICE.userName, ["CREATE_CONNECTION"]);
      fetchMock.mockClear();
    });

    // A rollback of a failed grant beside the sibling says "grant", but it
    // removes this request's grants, so it is a revoke too.
    it.each(["revoke", "grant"] as const)(
      "revokes beside an open sibling whose stored grant names it, leaving it in place, when the call says %s",
      async (operation) => {
        await expect(
          setPolicies(operation, { policies: sibling, requestGrants: orders })
        ).resolves.toBeNull();

        expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual(
          []
        );
        expect(fake.held("schema/main.sales", ALICE.userName)).toEqual([]);
        expect(fake.held("catalog/main", ALICE.userName).sort()).toEqual([
          "CREATE_CONNECTION",
          "USE_CATALOG",
        ]);
        expect(
          patches().filter((p) => JSON.stringify(p).includes('"add"'))
        ).toEqual([]);
      }
    );

    it("never adds it back on a revoke, even repairing a grant shared with a sibling", async () => {
      // Someone removed both grants this request shares with the sibling.
      fake.state.grants.get("catalog/main")?.delete(ALICE.userName);

      await expect(
        revoke({ policies: sibling, requestGrants: [...orders, retired] })
      ).resolves.toBeNull();

      expect(
        patches().filter((p) => JSON.stringify(p).includes('"add"'))
      ).toEqual([
        {
          securable: "catalog/main",
          changes: [{ principal: ALICE.userName, add: ["USE_CATALOG"] }],
        },
      ]);
      expect(fake.held("catalog/main", ALICE.userName)).toEqual([
        "USE_CATALOG",
      ]);
    });

    // Neither call removes anything, so each is a grant.
    it.each([
      ["this request's own grants", [...orders, retired], [...orders, retired]],
      ["an open sibling's grants", [...orders, retired], orders],
    ])(
      "refuses a grant whose policies name it in %s, before calling Databricks",
      async (_, policies, requestGrants) => {
        await expect(grant({ policies, requestGrants })).rejects.toMatchObject({
          message:
            "A grant's policies may only name privileges P0 grants, but this one's include CREATE_CONNECTION@catalog:main",
          data: { type: "validation_error" },
        });
        expect(fetchMock).not.toHaveBeenCalled();
      }
    );
  });

  it("names the email as the principal of every grant PATCH", async () => {
    await grant({
      policies: selectOnTable("orders"),
      requestGrants: selectOnTable("orders"),
    });

    expect(patches().map(({ changes }) => changes)).toEqual([
      [{ principal: ALICE.userName, add: ["USE_CATALOG"] }],
      [{ principal: ALICE.userName, add: ["USE_SCHEMA"] }],
      [{ principal: ALICE.userName, add: ["SELECT"] }],
    ]);
  });

  describe("a principal Databricks doesn't know", () => {
    const orders = selectOnTable("orders");

    const unknownUser = (email: string) => ({
      message: unknownUserMessage(email),
      data: {
        type: "object_not_found",
        payload: { query: email, unknownPrincipal: true },
      },
    });

    it.each([404, 400])(
      "fails a grant whose PATCH Databricks answers %i PRINCIPAL_DOES_NOT_EXIST, saying to add the user",
      async (status) => {
        fake.state.unknownPrincipalStatus = status;

        await expect(
          grant({
            policies: orders,
            requestGrants: orders,
            userId: "carol@example.com",
          })
        ).rejects.toMatchObject(unknownUser("carol@example.com"));
        // A grant stops at its first failure.
        expect(patches()).toHaveLength(1);
      }
    );

    describe("on a revoke, once P0 granted to it", () => {
      beforeEach(async () => {
        await grant({ policies: orders, requestGrants: orders });
        fake.state.principals.delete(ALICE.userName);
        fetchMock.mockClear();
        warn.mockClear();
      });

      it("counts as revoked, stopping at the first call and skipping the read-back", async () => {
        await expect(
          revoke({ policies: [], requestGrants: orders })
        ).resolves.toBeNull();

        expect(patches().map((p) => p.securable)).toEqual([
          "table/main.sales.orders",
        ]);
        expect(
          databricksCalls().filter(
            (call) =>
              call.init.method === "GET" && call.url.includes(UC_PERMISSIONS)
          )
        ).toEqual([]);
        expect(warn).toHaveBeenCalledWith(
          "user not found on revoke; treating as revoked"
        );
      });

      // A principal Databricks doesn't know holds nothing on the metastore,
      // so an earlier failure left nothing behind either.
      it("counts as revoked even after another call failed first", async () => {
        // The table's PATCH fails, then the schema's finds no principal.
        fake.state.errors.set("table/main.sales.orders", {
          status: 503,
          errorCode: "TEMPORARILY_UNAVAILABLE",
        });

        await expect(
          revoke({ policies: [], requestGrants: orders })
        ).resolves.toBeNull();
        expect(patches().map((p) => p.securable)).toEqual([
          "table/main.sales.orders",
          "schema/main.sales",
        ]);
      });
    });

    // One securable each, so the read-back is the first call that finds
    // the principal gone.
    const useCatalog = [policy("catalog", "main", "USE_CATALOG")];

    it("counts a revoke as done when the read-back finds the principal gone", async () => {
      await grant({ policies: useCatalog, requestGrants: useCatalog });
      fake.state.forgetsPrincipalsAfter = "PATCH";
      fake.state.unknownPrincipalFailsReads = true;
      fetchMock.mockClear();
      warn.mockClear();

      await expect(
        revoke({ policies: [], requestGrants: useCatalog })
      ).resolves.toBeNull();
      expect(databricksCalls().map((call) => call.init.method)).toEqual([
        "PATCH",
        "GET",
      ]);
      expect(warn).toHaveBeenCalledWith(
        "user not found on revoke; treating as revoked"
      );
    });

    it("still fails a grant whose read-back finds the principal gone", async () => {
      fake.state.forgetsPrincipalsAfter = "PATCH";
      fake.state.unknownPrincipalFailsReads = true;

      await expect(
        grant({ policies: useCatalog, requestGrants: useCatalog })
      ).rejects.toMatchObject(unknownUser(ALICE.userName));
      expect(
        databricksCalls()
          .filter((call) => !isBinding(call.url))
          .map((call) => call.init.method)
      ).toEqual(["GET", "PATCH", "GET"]);
    });

    it("still fails a revoke whose read-back showed a mismatch before it found the principal gone", async () => {
      await grant({ policies: orders, requestGrants: orders });
      // The catalog keeps its grant, and the first read-back, of the
      // catalog, is the last one that finds the principal.
      fake.state.ignoresPatches.add("catalog/main");
      fake.state.forgetsPrincipalsAfter = "GET";
      fake.state.unknownPrincipalFailsReads = true;

      await expect(
        revoke({ policies: [], requestGrants: orders })
      ).rejects.toThrow(/catalog main still has USE_CATALOG/);
    });
  });

  it.each([
    ["a group name", "data-team"],
    ["the workspace admins group", "admins"],
    ["a service principal's application ID", APPLICATION_ID],
  ])(
    "rejects %s, which isn't an email, as a userId before calling Databricks",
    async (_, userId) => {
      // The userId parser refuses anything that isn't an email. A service
      // principal's Unity Catalog principal is its application ID, so the
      // connector can't name itself.
      expect(() => spec.userId(userId)).toThrow();
      await expect(
        grant({
          policies: selectOnTable("orders"),
          requestGrants: selectOnTable("orders"),
          userId,
        })
      ).rejects.toThrow(/email/i);
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it.each(["MANAGE", "ALL_PRIVILEGES", "OWNERSHIP", "EXTERNAL_USE_SCHEMA"])(
    "never grants %s: policies refuse it before calling Databricks",
    async (privilege) => {
      const forbidden = policy("catalog", "main", privilege);

      await expect(
        grant({ policies: [forbidden], requestGrants: [forbidden] })
      ).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it.each([
    ["no error code", ""],
    ["the generic NOT_FOUND", "NOT_FOUND"],
    ["the generic RESOURCE_DOES_NOT_EXIST", "RESOURCE_DOES_NOT_EXIST"],
  ])("doesn't treat a 404 with %s as already revoked", async (_, errorCode) => {
    const orders = selectOnTable("orders");
    await grant({ policies: orders, requestGrants: orders });
    fake.state.errors.set("table/main.sales.orders", {
      status: 404,
      errorCode,
    });

    await expect(
      revoke({ policies: [], requestGrants: orders })
    ).rejects.toMatchObject({
      data: { payload: { status: 404 } },
    });
    expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([
      "SELECT",
    ]);
  });

  it("doesn't treat a TABLE_DOES_NOT_EXIST that isn't a 404 as already revoked", async () => {
    const orders = selectOnTable("orders");
    await grant({ policies: orders, requestGrants: orders });
    fake.state.errors.set("table/main.sales.orders", {
      status: 400,
      errorCode: "TABLE_DOES_NOT_EXIST",
    });

    await expect(
      revoke({ policies: [], requestGrants: orders })
    ).rejects.toMatchObject({
      data: { payload: { status: 400, errorCode: "TABLE_DOES_NOT_EXIST" } },
    });
    expect(fake.held("table/main.sales.orders", ALICE.userName)).toEqual([
      "SELECT",
    ]);
  });

  it("treats revoking from a dropped securable as done", async () => {
    const orders = selectOnTable("orders");
    await grant({ policies: orders, requestGrants: orders });
    fake.state.errors.set("table/main.sales.orders", {
      status: 404,
      errorCode: "TABLE_DOES_NOT_EXIST",
    });

    await expect(
      revoke({ policies: [], requestGrants: orders })
    ).resolves.toBeNull();

    expect(fake.held("schema/main.sales", ALICE.userName)).toEqual([]);
    expect(fake.held("catalog/main", ALICE.userName)).toEqual([]);
  });

  it("warns about a securable dropped between its revoke and the read-back", async () => {
    const orders = selectOnTable("orders");
    await grant({ policies: orders, requestGrants: orders });
    fake.state.dropsAfterPatch.add("table/main.sales.orders");
    warn.mockClear();

    await expect(
      revoke({ policies: [], requestGrants: orders })
    ).resolves.toBeNull();

    expect(warn).toHaveBeenCalledWith(
      { securable: { type: "table", fullName: "main.sales.orders" } },
      "securable not found on revoke; treating as revoked"
    );
  });

  it("says P0's principal can't manage privileges on the catalog when Databricks refuses the change", async () => {
    const orders = selectOnTable("orders");
    await grant({ policies: orders, requestGrants: orders });
    fake.state.errors.set("table/main.sales.orders", {
      status: 403,
      errorCode: "PERMISSION_DENIED",
    });

    await expect(
      revoke({ policies: [], requestGrants: orders })
    ).rejects.toMatchObject({
      message:
        "P0's service principal can't manage privileges on catalog main. Check that it holds MANAGE there, for example by re-applying the catalog's Terraform.",
      data: {
        type: "insufficient_privileges",
        payload: { catalog: "main", fullName: "main.sales.orders" },
      },
    });
  });

  it("fails when the permissions read back don't match", async () => {
    fake.state.ignoresPatches.add("table/main.sales.orders");

    await expect(
      grant({
        policies: selectOnTable("orders"),
        requestGrants: selectOnTable("orders"),
      })
    ).rejects.toThrow(/table main\.sales\.orders is missing SELECT/);
  });

  it("fails when a revoked privilege is still there afterwards", async () => {
    const orders = selectOnTable("orders");
    await grant({ policies: orders, requestGrants: orders });
    fake.state.ignoresPatches.add("table/main.sales.orders");

    await expect(
      revoke({ policies: [], requestGrants: orders })
    ).rejects.toThrow(/table main\.sales\.orders still has SELECT/);
  });
});

describe("list", () => {
  const workspaceContext = {
    ...accountContext(),
    workspaceId: WORKSPACE_ID,
    workspaceUrl: WORKSPACE_URL,
  };
  const list = (
    query: Parameters<ReturnType<typeof caller>["list"]>[0]["query"]
  ) => caller().list({ query });

  /** Queues pages for a UC list call with the given query string. */
  const queuePages = (path: string, query: string, pages: unknown[]) => {
    fake.state.lists[`/api/2.1/unity-catalog/${path}?${query}`] = pages.map(
      (page) => jsonResponse(page)
    );
  };

  /** Asserts the lister bound first, then called only the workspace. */
  const expectOnlyBoundWorkspaceCalls = () => {
    const urls = databricksCalls().map((call) => call.url);
    expect(urls[0]).toBe(`${WORKSPACE_URL}${METASTORE_ASSIGNMENT}`);
    expect(urls.length).toBeGreaterThan(1);
    expect(urls.every((url) => url.startsWith(`${WORKSPACE_URL}/`))).toBe(true);
  };

  // P0 lists workspaces from its installed items, which needs no account
  // admin.
  it("has no workspaces query", async () => {
    const workspaces = { type: "workspaces", context: accountContext() };

    // @ts-expect-error the query is gone: the parser must refuse it
    await expect(list(workspaces)).rejects.toThrow();
    expect(() => spec.listerQuery(workspaces)).toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  describe("metastore", () => {
    const metastore = () =>
      list({ type: "metastore", context: workspaceContext });

    it("returns the metastore ID the binding read, and calls nothing else", async () => {
      const items = await metastore();

      expect(items).toEqual([{ key: METASTORE_ID, value: METASTORE_ID }]);
      expect(spec.listerResponse(items)).toEqual(items);
      expect(databricksCalls().map((call) => call.url)).toEqual([
        `${WORKSPACE_URL}${METASTORE_ASSIGNMENT}`,
      ]);
    });

    it("fails for a workspace with no metastore, which can't be bound", async () => {
      fake.state.binding = jsonResponse(
        { error_code: "METASTORE_DOES_NOT_EXIST", message: "none" },
        { status: 404 }
      );

      await expect(metastore()).rejects.toMatchObject({
        message: `Databricks workspace ${WORKSPACE_ID} has no Unity Catalog metastore. P0 needs one to confirm the workspace's URL. Assign the workspace a metastore, then try again.`,
        data: { type: "validation_error" },
      });
    });

    it("fails for a URL that answers for another workspace", async () => {
      fake.state.binding = bindingResponse("42");

      await expect(metastore()).rejects.toMatchObject({
        data: { type: "validation_error" },
      });
    });

    it("passes an upstream error through the usual mapping", async () => {
      fake.state.binding = jsonResponse(
        { error_code: "TEMPORARILY_UNAVAILABLE", message: "try later" },
        { status: 503 }
      );

      await expect(metastore()).rejects.toMatchObject({
        data: { type: "upstream_unavailable", payload: { status: 503 } },
      });
    });

    it("rejects a workspace ID that isn't digits before calling Databricks", async () => {
      await expect(
        list({
          type: "metastore",
          context: { ...workspaceContext, workspaceId: "../1" },
        })
      ).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  it("binds before listing, and never lists through a URL that answers for another workspace", async () => {
    fake.state.binding = bindingResponse("42");
    queuePages("catalogs", "max_results=0", [{ catalogs: [{ name: "main" }] }]);

    await expect(
      list({ type: "catalogs", context: workspaceContext })
    ).rejects.toMatchObject({ data: { type: "validation_error" } });
    expect(
      databricksCalls().filter((call) => call.url.includes("/catalogs"))
    ).toEqual([]);
  });

  it("lists catalogs across pages", async () => {
    queuePages("catalogs", "max_results=0", [
      { catalogs: [{ name: "main" }], next_page_token: "p2" },
    ]);
    queuePages("catalogs", "max_results=0&page_token=p2", [
      { catalogs: [{ name: "dev" }] },
    ]);

    const items = await list({ type: "catalogs", context: workspaceContext });

    expect(items).toEqual([
      { key: "main", value: "main" },
      { key: "dev", value: "dev" },
    ]);
    expect(spec.listerResponse(items)).toEqual(items);
    expect(databricksCalls().map((call) => call.url)).toEqual([
      `${WORKSPACE_URL}${METASTORE_ASSIGNMENT}`,
      `${WORKSPACE_URL}/api/2.1/unity-catalog/catalogs?max_results=0`,
      `${WORKSPACE_URL}/api/2.1/unity-catalog/catalogs?max_results=0&page_token=p2`,
    ]);
  });

  it("lists a catalog's schemas", async () => {
    queuePages("schemas", "catalog_name=main&max_results=0", [
      { schemas: [{ name: "sales", full_name: "main.sales" }] },
    ]);

    const items = await list({
      type: "schemas",
      context: workspaceContext,
      catalog: "main",
    });

    expect(items).toEqual([{ key: "sales", value: "sales" }]);
    expect(spec.listerResponse(items)).toEqual(items);
    expectOnlyBoundWorkspaceCalls();
  });

  it.each(["tables", "volumes", "functions"] as const)(
    "lists a schema's %s",
    async (type) => {
      queuePages(type, "catalog_name=main&schema_name=sales&max_results=0", [
        { [type]: [{ name: "orders", full_name: "main.sales.orders" }] },
      ]);

      const items = await list({
        type,
        context: workspaceContext,
        catalog: "main",
        schema: "sales",
      });

      expect(items).toEqual([{ key: "orders", value: "orders" }]);
      expect(spec.listerResponse(items)).toEqual(items);
      expectOnlyBoundWorkspaceCalls();
    }
  );

  it("lists a user's direct grants on each securable", async () => {
    fake.grant("catalog/main", ALICE.userName, ["USE_CATALOG"]);
    fake.grant("table/main.sales.orders", ALICE.userName, ["SELECT", "MODIFY"]);
    fake.grant("table/main.sales.orders", BOB.userName, ["SELECT"]);

    const items = await list({
      type: "directGrants",
      context: workspaceContext,
      userName: ALICE.userName,
      securables: [
        { type: "catalog", fullName: "main" },
        { type: "schema", fullName: "main.sales" },
        { type: "table", fullName: "main.sales.orders" },
      ],
    });

    expect(items).toEqual([
      {
        key: "USE_CATALOG@catalog:main",
        value: "USE_CATALOG",
        group: "catalog:main",
      },
      {
        key: "MODIFY@table:main.sales.orders",
        value: "MODIFY",
        group: "table:main.sales.orders",
      },
      {
        key: "SELECT@table:main.sales.orders",
        value: "SELECT",
        group: "table:main.sales.orders",
      },
    ]);
    expect(spec.listerResponse(items)).toEqual(items);
    expectOnlyBoundWorkspaceCalls();
  });

  // Whether Databricks reports an unknown principal on a read at all is
  // unverified (ticket 22). When it does, the requestor learns at submission.
  it.each([404, 400])(
    "says to add the user when Databricks answers a direct grants read %i PRINCIPAL_DOES_NOT_EXIST",
    async (status) => {
      fake.state.unknownPrincipalFailsReads = true;
      fake.state.unknownPrincipalStatus = status;

      await expect(
        list({
          type: "directGrants",
          context: workspaceContext,
          userName: "carol@example.com",
          securables: [{ type: "catalog", fullName: "main" }],
        })
      ).rejects.toMatchObject({
        message: unknownUserMessage("carol@example.com"),
        data: {
          type: "object_not_found",
          payload: { query: "carol@example.com" },
        },
      });
    }
  );
});
