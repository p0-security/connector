import { createLogger } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeAuth0,
  type FakeOrganization,
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
import { rateLimitRetry } from "../../../auth0/api.ts";
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
const { organization } = connector.auth0.accesses;

const ALICE_ID = "auth0|alice";
const ORG = "org_1";
const MEMBERS_PATH = "/api/v2/organizations/org_1/members";
const ROLES_PATH = "/api/v2/organizations/org_1/members/auth0%7Calice/roles";

type Context = {
  tenant: string;
  clientId: string;
  clientSecret: typeof CREDENTIALS.clientSecret;
  requestId: string;
  auth0UserId: string;
  organizationId: string;
  roleId?: string;
  wasMember: boolean;
  priorRoleIds: string[];
};

const contextFor = (change: Partial<Context> = {}): Context => ({
  ...CREDENTIALS,
  requestId: "req-1",
  auth0UserId: ALICE_ID,
  organizationId: ORG,
  wasMember: false,
  priorRoleIds: [],
  ...change,
});

let auth0: FakeAuth0;
let alice: FakeUser;
let org: FakeOrganization;
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
  org = { id: ORG, name: "acme", members: new Map() };
  auth0.organizations.push(org, {
    id: "org_2",
    name: "other",
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
  rateLimitRetry.waitMs = 10_000;
  vi.unstubAllGlobals();
});

const grant = (context: Context, email = EMAIL) =>
  organization.setPoliciesForUser({
    userId: email,
    userBody: email,
    policies: [
      {
        organizationId: context.organizationId,
        ...(context.roleId === undefined ? {} : { roleId: context.roleId }),
      },
    ],
    context,
  });

const revoke = (context: Context, email = EMAIL) =>
  organization.setPoliciesForUser({
    userId: email,
    userBody: email,
    policies: [null],
    context,
  });

/** Alice's standing in org_1, or `undefined` when she isn't a member. */
const standing = () => org.members.get(ALICE_ID);

/** Everything else about Alice, which no call may change. */
const elsewhere = () =>
  structuredClone({
    roles: alice.roles,
    permissions: alice.permissions,
    other: [...(auth0.organizations[1]?.members ?? [])],
  });

describe("the table", () => {
  it("adds and removes the membership for a non-member who asks for no role", async () => {
    const context = contextFor();

    await grant(context);
    expect(standing()).toEqual([]);
    await revoke(context);

    expect(standing()).toBeUndefined();
    expect(auth0.writes()).toEqual([
      { method: "POST", path: MEMBERS_PATH, body: { members: [ALICE_ID] } },
      { method: "DELETE", path: MEMBERS_PATH, body: { members: [ALICE_ID] } },
    ]);
  });

  it("adds the membership then the role, and removes the role then the membership, for a non-member who asks for a role", async () => {
    const context = contextFor({ roleId: "rol_admin" });

    await grant(context);
    expect(standing()).toEqual(["rol_admin"]);
    await revoke(context);

    expect(standing()).toBeUndefined();
    expect(auth0.writes()).toEqual([
      { method: "POST", path: MEMBERS_PATH, body: { members: [ALICE_ID] } },
      { method: "POST", path: ROLES_PATH, body: { roles: ["rol_admin"] } },
      { method: "DELETE", path: ROLES_PATH, body: { roles: ["rol_admin"] } },
      { method: "DELETE", path: MEMBERS_PATH, body: { members: [ALICE_ID] } },
    ]);
  });

  it("adds and removes only the role for a member who doesn't hold it", async () => {
    org.members.set(ALICE_ID, ["rol_viewer"]);
    const context = contextFor({
      roleId: "rol_admin",
      wasMember: true,
      priorRoleIds: ["rol_viewer"],
    });

    await grant(context);
    expect(standing()).toEqual(["rol_viewer", "rol_admin"]);
    await revoke(context);

    expect(standing()).toEqual(["rol_viewer"]);
    expect(auth0.writes()).toEqual([
      { method: "POST", path: ROLES_PATH, body: { roles: ["rol_admin"] } },
      { method: "DELETE", path: ROLES_PATH, body: { roles: ["rol_admin"] } },
    ]);
  });

  // P0 refuses this request before it reaches the connector.
  it("refuses a member who asks for no role as unknown, and writes nothing", async () => {
    org.members.set(ALICE_ID, []);

    const data = await connectorError(() =>
      grant(contextFor({ wasMember: true }))
    );

    expect(data.type).toBe("unknown");
    expect(auth0.calls).toEqual([]);
  });

  it.each([
    ["a non-member without a role", contextFor()],
    ["a non-member with a role", contextFor({ roleId: "rol_admin" })],
    [
      "a member",
      contextFor({
        roleId: "rol_admin",
        wasMember: true,
        priorRoleIds: ["rol_viewer"],
      }),
    ],
  ])("leaves everything else about %s as it was", async (_case, context) => {
    if (context.wasMember) org.members.set(ALICE_ID, ["rol_viewer"]);
    const before = { standing: standing(), ...elsewhere() };

    await grant(context);
    await revoke(context);

    expect({ standing: standing(), ...elsewhere() }).toEqual(before);
  });
});

describe("a role that fails after the membership", () => {
  const context = contextFor({ roleId: "rol_admin" });

  beforeEach(() => {
    auth0.intercept((call) =>
      isCall("POST", ROLES_PATH)(call)
        ? failing(409, "The member has reached the maximum of 50 roles")
        : undefined
    );
  });

  it("removes the membership again, and fails as a dependency_violation", async () => {
    const data = await connectorError(() => grant(context));

    expect(data).toEqual({
      type: "dependency_violation",
      message:
        "Auth0 refused to assign the role in organization org_1: The member has reached the maximum of 50 roles. P0 removed the membership it had added.",
      payload: {
        organizationId: ORG,
        roleId: "rol_admin",
        userId: ALICE_ID,
        membershipRemoved: true,
      },
    });
    expect(standing()).toBeUndefined();
  });

  it("says so when the membership can't be removed either", async () => {
    auth0.intercept((call) => {
      if (isCall("POST", ROLES_PATH)(call)) return failing(500);
      if (isCall("DELETE", MEMBERS_PATH)(call)) return failing(500);
      return undefined;
    });

    const data = await connectorError(() => grant(context));

    expect(data.type).toBe("dependency_violation");
    expect(data.message).toBe(
      "Auth0 refused to assign the role in organization org_1: Internal Server Error. P0 added the membership but couldn't remove it again. Remove auth0|alice from org_1 by hand."
    );
    expect(data.payload).toMatchObject({ membershipRemoved: false });
    expect(standing()).toEqual([]);
  });

  // The framework then rolls the grant back with a revoke.
  it("leaves nothing for the rollback to break", async () => {
    await connectorError(() => grant(context));
    auth0.intercept(() => undefined);

    await revoke(context);

    expect(standing()).toBeUndefined();
  });
});

describe("a 409 for what isn't there", () => {
  it.each([
    ["the membership", MEMBERS_PATH],
    ["the role", ROLES_PATH],
  ])("fails a grant when it's for %s", async (_case, path) => {
    if (path === ROLES_PATH) org.members.set(ALICE_ID, []);
    auth0.intercept((call) =>
      isCall("POST", path)(call) ? failing(409, "Conflict") : undefined
    );

    const data = await connectorError(() =>
      grant(
        contextFor({
          roleId: "rol_admin",
          wasMember: path === ROLES_PATH,
        })
      )
    );

    expect(data.type).toBe("validation_error");
  });
});

describe("a membership found already there", () => {
  // Someone added the user after stage recorded it wasn't a member.
  it("is left alone when the role then fails", async () => {
    newTenant({ alreadyAssigned: failing(409, "Conflict") });
    org.members.set(ALICE_ID, []);
    auth0.intercept((call) =>
      isCall("POST", ROLES_PATH)(call) ? failing(500) : undefined
    );

    const data = await connectorError(() =>
      grant(contextFor({ roleId: "rol_admin" }))
    );

    expect(data.type).toBe("upstream_unavailable");
    expect(standing()).toEqual([]);
    expect(auth0.writes().map(({ method }) => method)).not.toContain("DELETE");
  });
});

describe("reruns", () => {
  it("grants twice, and the second grant succeeds", async () => {
    const context = contextFor({ roleId: "rol_admin" });

    await grant(context);
    await grant(context);

    expect(standing()).toEqual(["rol_admin"]);
  });

  it.each([
    ["a 409", failing(409, "Conflict")],
    [
      "a 400 that says it's already there",
      failing(400, "User is already a member"),
    ],
  ])("takes %s on a grant as already there", async (_case, reply) => {
    newTenant({ alreadyAssigned: reply });
    const context = contextFor({ roleId: "rol_admin" });
    org.members.set(ALICE_ID, ["rol_admin"]);

    await expect(grant(context)).resolves.toBeNull();
    expect(standing()).toEqual(["rol_admin"]);
  });

  it("revokes twice, and the second revoke succeeds", async () => {
    const context = contextFor({ roleId: "rol_admin" });
    await grant(context);

    await revoke(context);
    await revoke(context);

    expect(standing()).toBeUndefined();
  });

  it("never removes a member who was there before P0", async () => {
    org.members.set(ALICE_ID, ["rol_viewer"]);
    const context = contextFor({
      roleId: "rol_admin",
      wasMember: true,
      priorRoleIds: ["rol_viewer"],
    });

    await grant(context);
    await revoke(context);
    await revoke(context);
    await grant(context);
    await revoke(context);

    expect(standing()).toEqual(["rol_viewer"]);
    expect(auth0.writes().map(({ path }) => path)).not.toContain(MEMBERS_PATH);
  });

  it("never removes a role the member held before P0", async () => {
    org.members.set(ALICE_ID, ["rol_admin"]);

    await revoke(
      contextFor({
        roleId: "rol_admin",
        wasMember: true,
        priorRoleIds: ["rol_admin"],
      })
    );

    expect(standing()).toEqual(["rol_admin"]);
    expect(auth0.writes()).toEqual([]);
  });

  it("revokes a member who has already left", async () => {
    await expect(
      revoke(contextFor({ roleId: "rol_admin" }))
    ).resolves.toBeNull();
  });

  it("revokes in an organization that's gone", async () => {
    await expect(
      revoke(contextFor({ organizationId: "org_gone", roleId: "rol_admin" }))
    ).resolves.toBeNull();
  });
});

describe("a grant", () => {
  it("refuses an email outside the allowed domains, and asks Auth0 nothing", async () => {
    const data = await connectorError(() => grant(contextFor(), OUTSIDER));

    expect(data.payload).toMatchObject({ reason: "domain_not_allowed" });
    expect(auth0.calls).toEqual([]);
  });

  it("refuses when the Auth0 user no longer has the requestor's email, and writes nothing", async () => {
    alice.email = "someone@acme.com";

    const data = await connectorError(() => grant(contextFor()));

    expect(data.payload).toMatchObject({ reason: "user_changed" });
    expect(auth0.writes()).toEqual([]);
  });

  it("reports an organization that isn't there as object_not_found, and writes nothing", async () => {
    const data = await connectorError(() =>
      grant(contextFor({ organizationId: "org_gone" }))
    );

    expect(data).toMatchObject({
      type: "object_not_found",
      payload: { query: "organization org_gone" },
    });
    expect(standing()).toBeUndefined();
  });

  it("refuses an organization id that could change the URL", async () => {
    await expect(
      grant(contextFor({ organizationId: "../users" }))
    ).rejects.toThrow();
    expect(auth0.calls).toEqual([]);
  });
});

describe("a revoke", () => {
  it("isn't gated by the allowed domains", async () => {
    const context = contextFor();
    await grant(context);

    await revoke(context, OUTSIDER);

    expect(standing()).toBeUndefined();
  });

  it("fails when Auth0 refuses", async () => {
    auth0.intercept((call) =>
      call.method === "DELETE" ? failing(403, "Insufficient scope") : undefined
    );

    const data = await connectorError(() => revoke(contextFor()));

    expect(data.type).toBe("insufficient_privileges");
  });

  it("fails as a validation_error when Auth0 refuses before anything is removed", async () => {
    org.members.set(ALICE_ID, []);
    auth0.intercept((call) =>
      isCall("DELETE", MEMBERS_PATH)(call)
        ? failing(400, "Cannot remove the member")
        : undefined
    );

    const data = await connectorError(() => revoke(contextFor()));

    expect(data.type).toBe("validation_error");
    expect(standing()).toEqual([]);
  });

  it("fails as a dependency_violation when the membership is refused after the role is removed", async () => {
    org.members.set(ALICE_ID, ["rol_admin"]);
    auth0.intercept((call) =>
      isCall("DELETE", MEMBERS_PATH)(call)
        ? failing(400, "Cannot remove the member")
        : undefined
    );

    const data = await connectorError(() =>
      revoke(contextFor({ roleId: "rol_admin" }))
    );

    expect(data).toEqual({
      type: "dependency_violation",
      message:
        "Auth0 refused to remove auth0|alice from organization org_1: Cannot remove the member. P0 removed the role it had added, but auth0|alice is still a member. Fix what Auth0's reason names, or remove auth0|alice from org_1 in Auth0.",
      payload: {
        organizationId: ORG,
        userId: ALICE_ID,
        roleRemoved: true,
      },
    });
    expect(standing()).toEqual([]);
  });

  // A failure that isn't Auth0 refusing the removal keeps its own type after
  // the role is removed, so P0 still retries a rate limit or an outage rather
  // than asking an admin.
  it.each([
    [429, "rate_limited"],
    [503, "upstream_unavailable"],
    [403, "insufficient_privileges"],
  ])(
    "keeps a %i on the membership as %s after the role is removed",
    async (status, type) => {
      // A 429 is retried after a wait. This test only cares how it ends.
      rateLimitRetry.waitMs = 0;
      org.members.set(ALICE_ID, ["rol_admin"]);
      auth0.intercept((call) =>
        isCall("DELETE", MEMBERS_PATH)(call)
          ? failing(status, "Try again later")
          : undefined
      );

      const data = await connectorError(() =>
        revoke(contextFor({ roleId: "rol_admin" }))
      );

      expect(data.type).toBe(type);
    }
  );

  it("fails as a validation_error when the role was already gone", async () => {
    org.members.set(ALICE_ID, []);
    auth0.intercept((call) => {
      if (isCall("DELETE", ROLES_PATH)(call)) {
        return failing(404, "The role does not exist.");
      }
      if (isCall("DELETE", MEMBERS_PATH)(call)) {
        return failing(400, "Cannot remove the member");
      }
      return undefined;
    });

    const data = await connectorError(() =>
      revoke(contextFor({ roleId: "rol_admin" }))
    );

    expect(data.type).toBe("validation_error");
  });
});

describe("the policies", () => {
  it.each([
    ["none", []],
    ["two", [{ organizationId: ORG }, null]],
  ])("are refused as unknown when there are %s", async (_case, policies) => {
    const data = await connectorError(() =>
      organization.setPoliciesForUser({
        userId: EMAIL,
        userBody: EMAIL,
        policies,
        context: contextFor(),
      })
    );

    expect(data.type).toBe("unknown");
    expect(auth0.calls).toEqual([]);
  });
});

describe("what a grant acts on", () => {
  // The policy is what the framework wants granted. The context says what
  // P0 recorded, and drives a revoke.
  it("grants the policy's organization and role, not the context's", async () => {
    auth0.organizations.push({
      id: "org_3",
      name: "third",
      members: new Map(),
    });

    await organization.setPoliciesForUser({
      userId: EMAIL,
      userBody: EMAIL,
      policies: [{ organizationId: "org_3", roleId: "rol_viewer" }],
      context: contextFor({ organizationId: ORG, roleId: "rol_admin" }),
    });

    expect(
      auth0.organizations
        .find(({ id }) => id === "org_3")
        ?.members.get(ALICE_ID)
    ).toEqual(["rol_viewer"]);
    expect(standing()).toBeUndefined();
  });

  it("grants no role when the policy names none, whatever the context says", async () => {
    await organization.setPoliciesForUser({
      userId: EMAIL,
      userBody: EMAIL,
      policies: [{ organizationId: ORG }],
      context: contextFor({ roleId: "rol_admin" }),
    });

    expect(standing()).toEqual([]);
  });

  // A 409 can mean the member is at Auth0's 50-role cap.
  it("fails a 409 on the role when the member holds a different one", async () => {
    newTenant({ alreadyAssigned: failing(409, "Conflict") });
    org.members.set(ALICE_ID, ["rol_viewer"]);
    auth0.intercept((call) =>
      isCall("POST", ROLES_PATH)(call) ? failing(409, "Conflict") : undefined
    );

    const data = await connectorError(() =>
      grant(
        contextFor({
          roleId: "rol_admin",
          wasMember: true,
          priorRoleIds: ["rol_viewer"],
        })
      )
    );

    expect(data.type).toBe("validation_error");
  });

  it("revokes a member who asked for no role, writing nothing", async () => {
    org.members.set(ALICE_ID, []);

    await expect(
      revoke(contextFor({ wasMember: true, priorRoleIds: [] }))
    ).resolves.toBeNull();
    expect(auth0.writes()).toEqual([]);
    expect(standing()).toEqual([]);
  });

  it("says exactly why it refuses a member who asks for nothing", async () => {
    const data = await connectorError(() =>
      grant(contextFor({ wasMember: true }))
    );

    expect(data).toEqual({
      type: "unknown",
      message:
        "Nothing to grant: the user was already a member of org_1, and no role was requested",
      payload: { requestId: "req-1", organizationId: ORG },
    });
  });
});
