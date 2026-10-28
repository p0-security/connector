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
const { permission } = connector.auth0.accesses;

const ALICE_ID = "auth0|alice";
const API = "https://api.acme.com";
const PERMISSIONS_PATH = "/api/v2/users/auth0%7Calice/permissions";
const WRITE = { resourceServerIdentifier: API, permissionName: "write:things" };
const CONTEXT = {
  ...CREDENTIALS,
  requestId: "req-1",
  auth0UserId: ALICE_ID,
  ...WRITE,
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
    roles: ["rol_writer"],
    permissions: [{ api: API, name: "read:things" }],
  };
  auth0.users.push(alice);
  auth0.apis.push(
    {
      identifier: API,
      name: "Acme API",
      scopes: [{ value: "read:things" }, { value: "write:things" }],
    },
    // Another API with a permission of the same name.
    {
      identifier: "urn:other",
      name: "Other",
      scopes: [{ value: "write:things" }],
    }
  );
  auth0.roles.push({
    id: "rol_writer",
    name: "Writer",
    permissions: [{ api: API, name: "write:things" }],
  });
  auth0.organizations.push({
    id: "org_1",
    name: "acme",
    members: new Map([[ALICE_ID, []]]),
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
  permission.setPoliciesForUser({
    userId: email,
    userBody: email,
    policies: [
      {
        resourceServerIdentifier: context.resourceServerIdentifier,
        permissionName: context.permissionName,
      },
    ],
    context,
  });

const revoke = (context = CONTEXT, email = EMAIL) =>
  permission.setPoliciesForUser({
    userId: email,
    userBody: email,
    policies: [null],
    context,
  });

const direct = () => structuredClone(alice.permissions);

describe("a permission the user also holds through a role", () => {
  it("is granted directly", async () => {
    await grant();

    expect(alice.permissions).toEqual([
      { api: API, name: "read:things" },
      { api: API, name: "write:things" },
    ]);
  });

  it("is revoked only as a direct assignment, and the role keeps giving it", async () => {
    await grant();
    await revoke();

    expect(alice.permissions).toEqual([{ api: API, name: "read:things" }]);
    expect(alice.roles).toEqual(["rol_writer"]);
    expect(auth0.roles[0]?.permissions).toEqual([
      { api: API, name: "write:things" },
    ]);
  });
});

describe("a grant then a revoke", () => {
  it("leaves the user's direct permissions, roles and memberships as they were", async () => {
    const before = structuredClone({
      permissions: alice.permissions,
      roles: alice.roles,
      members: [...(auth0.organizations[0]?.members ?? [])],
    });

    await grant();
    await revoke();

    expect(
      structuredClone({
        permissions: alice.permissions,
        roles: alice.roles,
        members: [...(auth0.organizations[0]?.members ?? [])],
      })
    ).toEqual(before);
  });

  it("assigns and removes the one permission, by API and name", async () => {
    await grant();
    await revoke();

    const body = {
      permissions: [
        { resource_server_identifier: API, permission_name: "write:things" },
      ],
    };
    expect(auth0.writes()).toEqual([
      { method: "POST", path: PERMISSIONS_PATH, body },
      { method: "DELETE", path: PERMISSIONS_PATH, body },
    ]);
  });

  it("never touches the same-named permission on another API", async () => {
    alice.permissions.push({ api: "urn:other", name: "write:things" });

    await grant();
    await revoke();

    expect(alice.permissions).toContainEqual({
      api: "urn:other",
      name: "write:things",
    });
  });
});

describe("idempotency", () => {
  it("grants twice, and the second grant succeeds", async () => {
    await grant();
    await grant();

    expect(
      alice.permissions.filter(({ name }) => name === "write:things")
    ).toHaveLength(1);
  });

  it.each([
    ["a 409", failing(409, "Conflict")],
    [
      "a 400 that says it's already assigned",
      failing(400, "Permission already assigned"),
    ],
  ])(
    "takes %s on a grant as already assigned, once it reads so",
    async (_case, reply) => {
      newTenant({ alreadyAssigned: reply });
      alice.permissions.push({ api: API, name: "write:things" });

      await expect(grant()).resolves.toBeNull();
    }
  );

  // Only a direct assignment counts: through the role alone, it isn't there.
  it("fails a 409 when the permission is held only through a role", async () => {
    auth0.intercept((call) =>
      isCall("POST", PERMISSIONS_PATH)(call)
        ? failing(409, "Conflict")
        : undefined
    );

    const data = await connectorError(() => grant());

    expect(data.type).toBe("validation_error");
  });

  it("revokes twice, and the second revoke succeeds", async () => {
    await grant();
    await revoke();
    await revoke();

    expect(direct()).toEqual([{ api: API, name: "read:things" }]);
  });

  it("takes a 404 on a revoke as already gone", async () => {
    await expect(
      revoke({ ...CONTEXT, auth0UserId: "auth0|gone" })
    ).resolves.toBeNull();
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

    expect(data.payload).toMatchObject({ reason: "user_changed" });
    expect(auth0.writes()).toEqual([]);
  });

  it("reports a permission the API doesn't define as object_not_found", async () => {
    const data = await connectorError(() =>
      grant({ ...CONTEXT, permissionName: "delete:things" })
    );

    expect(data).toMatchObject({
      type: "object_not_found",
      payload: { query: `permission delete:things on ${API}` },
    });
  });
});

describe("a revoke", () => {
  it("isn't gated by the allowed domains", async () => {
    await grant();

    await revoke(CONTEXT, OUTSIDER);

    expect(direct()).toEqual([{ api: API, name: "read:things" }]);
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
    ["two", [WRITE, null]],
  ])("are refused as unknown when there are %s", async (_case, policies) => {
    const data = await connectorError(() =>
      permission.setPoliciesForUser({
        userId: EMAIL,
        userBody: EMAIL,
        policies,
        context: CONTEXT,
      })
    );

    expect(data).toEqual({
      type: "unknown",
      message: `Expected exactly 1 policy for an Auth0 permission, got ${policies.length}`,
      payload: { requestId: "req-1", nPolicies: policies.length },
    });
    expect(auth0.calls).toEqual([]);
  });

  it.each([
    ["an empty API", { ...WRITE, resourceServerIdentifier: "" }],
    ["an empty name", { ...WRITE, permissionName: "" }],
    ["no name", { resourceServerIdentifier: API }],
  ])("refuses a policy with %s", async (_case, policy) => {
    await expect(
      permission.setPoliciesForUser({
        userId: EMAIL,
        userBody: EMAIL,
        policies: [policy as typeof WRITE],
        context: CONTEXT,
      })
    ).rejects.toThrow();
    expect(auth0.calls).toEqual([]);
  });
});

describe("the read-back after a 409", () => {
  // The same permission name on another API isn't this permission.
  it("fails when the user holds the name only on another API", async () => {
    alice.permissions.push({ api: "urn:other", name: "write:things" });
    auth0.intercept((call) =>
      isCall("POST", PERMISSIONS_PATH)(call)
        ? failing(409, "Conflict")
        : undefined
    );

    const data = await connectorError(() => grant());

    expect(data.type).toBe("validation_error");
  });
});
