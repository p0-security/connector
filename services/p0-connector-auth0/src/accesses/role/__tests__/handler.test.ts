import { createLogger } from "@p0security/connector";
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
import { connectorRouter, t } from "../../../router.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const getClientSecret = vi.hoisted(() => vi.fn());
vi.mock("../../../secrets.ts", () => ({ getClientSecret }));

// Read when the first email is checked, as a deployment's is.
vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

const OUTSIDER = "mallory@evil.com";

const logger = createLogger();
logger.level = "silent";
const connector = t.createCallerFactory(connectorRouter)({ logger });
const { role } = connector.auth0.accesses;

const ALICE_ID = "auth0|alice";
const CONTEXT = {
  ...CREDENTIALS,
  requestId: "req-1",
  auth0UserId: ALICE_ID,
  roleId: "rol_admin",
};

let auth0: FakeAuth0;
let alice: FakeUser;
let versions = 0;

const newTenant = (
  options: Partial<Parameters<typeof newFakeAuth0>[0]> = {}
) => {
  auth0 = newFakeAuth0({
    tenant: TENANT,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    ...options,
  });
  vi.stubGlobal("fetch", auth0.fetch);
  alice = {
    user_id: ALICE_ID,
    email: EMAIL,
    connection: "Username-Password-Authentication",
    roles: ["rol_viewer"],
    permissions: [{ api: "urn:api", name: "read:things" }],
  };
  auth0.users.push(alice);
  auth0.roles.push(
    { id: "rol_admin", name: "Admin", permissions: [] },
    { id: "rol_viewer", name: "Viewer", permissions: [] }
  );
  auth0.organizations.push({
    id: "org_1",
    name: "acme",
    members: new Map([[ALICE_ID, ["rol_viewer"]]]),
  });
};

beforeEach(() => {
  newTenant();
  getClientSecret.mockReset();
  getClientSecret.mockImplementation(async () => ({
    secret: CLIENT_SECRET,
    version: `version-${++versions}`,
  }));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const grant = (context = CONTEXT, email = EMAIL) =>
  role.setPoliciesForUser({
    userId: email,
    userBody: email,
    policies: [{ roleId: context.roleId }],
    context,
  });

const revoke = (context = CONTEXT, email = EMAIL) =>
  role.setPoliciesForUser({
    userId: email,
    userBody: email,
    policies: [null],
    context,
  });

/** What's assigned to Alice, besides the role. */
const untouched = () => ({
  permissions: structuredClone(alice.permissions),
  memberships: structuredClone([...(auth0.organizations[0]?.members ?? [])]),
});

describe("idempotency", () => {
  it("grants twice, and the second grant succeeds", async () => {
    await grant();
    await grant();

    expect(alice.roles).toEqual(["rol_viewer", "rol_admin"]);
  });

  it.each([
    ["a 409", failing(409, "Conflict")],
    [
      "a 400 that says it's already assigned",
      failing(400, "Role already assigned to user"),
    ],
  ])(
    "takes %s on a grant as the role already assigned",
    async (_case, reply) => {
      newTenant({ alreadyAssigned: reply });
      alice.roles.push("rol_admin");

      await expect(grant()).resolves.toBeNull();
    }
  );

  // A member at Auth0's role cap gets a 409 too.
  it("fails a 409 on a grant when the role turns out not to be assigned", async () => {
    newTenant({ alreadyAssigned: failing(409, "Conflict") });
    auth0.intercept((call) =>
      isCall("POST", "/api/v2/users/auth0%7Calice/roles")(call)
        ? failing(409, "Too many roles")
        : undefined
    );

    const data = await connectorError(() => grant());

    expect(data.type).toBe("validation_error");
    expect(alice.roles).toEqual(["rol_viewer"]);
  });

  it("doesn't take any other 400 on a grant as already assigned", async () => {
    auth0.intercept((call) =>
      isCall("POST", `/api/v2/users/auth0%7Calice/roles`)(call)
        ? failing(400, "Payload validation error", "invalid_body")
        : undefined
    );

    const data = await connectorError(() => grant());

    expect(data.type).toBe("validation_error");
    expect(data.message).toBe(
      `Auth0 tenant ${TENANT} refused the connector's request (400): Payload validation error`
    );
  });

  it("revokes twice, and the second revoke succeeds", async () => {
    alice.roles.push("rol_admin");

    await revoke();
    await revoke();

    expect(alice.roles).toEqual(["rol_viewer"]);
  });

  it("takes a 404 on a revoke as the role already gone", async () => {
    await expect(
      revoke({ ...CONTEXT, auth0UserId: "auth0|gone" })
    ).resolves.toBeNull();
  });
});

describe("a grant then a revoke", () => {
  it("leaves the user's roles, permissions and memberships as they were", async () => {
    const before = { roles: [...alice.roles], ...untouched() };

    await grant();
    expect(alice.roles).toContain("rol_admin");
    await revoke();

    expect({ roles: alice.roles, ...untouched() }).toEqual(before);
  });

  it("assigns and removes only the one role, to the user P0 found", async () => {
    await grant();
    await revoke();

    expect(auth0.writes()).toEqual([
      {
        method: "POST",
        path: "/api/v2/users/auth0%7Calice/roles",
        body: { roles: ["rol_admin"] },
      },
      {
        method: "DELETE",
        path: "/api/v2/users/auth0%7Calice/roles",
        body: { roles: ["rol_admin"] },
      },
    ]);
  });

  it("assigns the policy's role, and removes the request's", async () => {
    await role.setPoliciesForUser({
      userId: EMAIL,
      userBody: EMAIL,
      policies: [{ roleId: "rol_viewer" }],
      context: CONTEXT,
    });
    await revoke();

    expect(auth0.writes().map(({ body }) => body)).toEqual([
      { roles: ["rol_viewer"] },
      { roles: ["rol_admin"] },
    ]);
  });
});

describe("a grant", () => {
  it("refuses an email outside the allowed domains, and asks Auth0 nothing", async () => {
    const data = await connectorError(() => grant(CONTEXT, OUTSIDER));

    expect(data.payload).toMatchObject({ reason: "domain_not_allowed" });
    expect(auth0.calls).toEqual([]);
  });

  it("refuses when the Auth0 user no longer has the requestor's email, and writes nothing", async () => {
    alice.email = "someone@acme.com";

    const data = await connectorError(() => grant());

    expect(data).toMatchObject({
      type: "validation_error",
      payload: { reason: "user_changed", userId: ALICE_ID },
    });
    expect(auth0.writes()).toEqual([]);
  });

  it("refuses when the Auth0 user is gone, and writes nothing", async () => {
    const data = await connectorError(() =>
      grant({ ...CONTEXT, auth0UserId: "auth0|gone" })
    );

    expect(data.payload).toMatchObject({ reason: "user_changed" });
    expect(auth0.writes()).toEqual([]);
  });

  it("reports a role that isn't there as object_not_found", async () => {
    const data = await connectorError(() =>
      grant({ ...CONTEXT, roleId: "rol_gone" })
    );

    expect(data).toMatchObject({
      type: "object_not_found",
      payload: { query: "role rol_gone" },
    });
  });

  it("refuses a role id that could change the URL", async () => {
    await expect(grant({ ...CONTEXT, roleId: "../x" })).rejects.toThrow();
    expect(auth0.calls).toEqual([]);
  });
});

describe("a revoke", () => {
  // So tightening the pattern can't strand a role granted earlier.
  it("isn't gated by the allowed domains", async () => {
    alice.roles.push("rol_admin");

    await revoke(CONTEXT, OUTSIDER);

    expect(alice.roles).toEqual(["rol_viewer"]);
  });

  it("removes the role whatever the user's email is now", async () => {
    alice.roles.push("rol_admin");
    alice.email = "someone@acme.com";

    await revoke();

    expect(alice.roles).toEqual(["rol_viewer"]);
    expect(auth0.apiCalls().map(({ method }) => method)).toEqual(["DELETE"]);
  });

  it("fails when Auth0 refuses", async () => {
    auth0.intercept((call) =>
      call.method === "DELETE" ? failing(403, "Insufficient scope") : undefined
    );

    const data = await connectorError(() => revoke());

    expect(data.type).toBe("insufficient_privileges");
  });
});

describe("the policies", () => {
  it.each([
    ["none", []],
    ["two", [{ roleId: "rol_admin" }, null]],
  ])("are refused as unknown when there are %s", async (_case, policies) => {
    const data = await connectorError(() =>
      role.setPoliciesForUser({
        userId: EMAIL,
        userBody: EMAIL,
        policies,
        context: CONTEXT,
      })
    );

    expect(data).toEqual({
      type: "unknown",
      message: `Expected exactly 1 policy for an Auth0 role, got ${policies.length}`,
      payload: { requestId: "req-1", nPolicies: policies.length },
    });
    expect(auth0.calls).toEqual([]);
  });
});

describe("the user primitives", () => {
  it("provisions the requestor's email without asking Auth0", async () => {
    await expect(
      role.provisionUser({ userBody: EMAIL, context: CONTEXT })
    ).resolves.toBe(EMAIL);
    await expect(
      role.identifyUser({ userBody: EMAIL, context: CONTEXT })
    ).resolves.toBe(EMAIL);
    await expect(
      role.deleteUser({ userId: EMAIL, userBody: EMAIL, context: CONTEXT })
    ).resolves.toBeNull();
    expect(auth0.calls).toEqual([]);
  });
});

describe("list", () => {
  it("answers the shared queries", async () => {
    await expect(
      role.list({ query: { type: "roles", context: CREDENTIALS } })
    ).resolves.toEqual([
      { key: "rol_admin", value: "Admin" },
      { key: "rol_viewer", value: "Viewer" },
    ]);
  });
});
