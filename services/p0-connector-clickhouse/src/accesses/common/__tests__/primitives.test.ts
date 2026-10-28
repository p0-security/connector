import { cloneDeep } from "lodash-es";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeCloud,
  type FakePolicy,
  type FakeRole,
  failing,
  isCall,
  newSeededCloud,
} from "../../../__tests__/fake-cloud.ts";
import {
  ALLOWED_PATTERN,
  EMAIL,
  KEY_ID,
  KEY_SECRET,
  ORGANIZATION_ID,
  SERVICE_ID,
} from "../../../__tests__/fixtures.ts";
import {
  connectorError,
  newRecordingLogger,
} from "../../../__tests__/helpers.ts";
import {
  BASE_POLICIES,
  CONTEXT,
  DESCRIPTION,
  MEMBER,
  REQUEST_ID,
  ROLE_NAME,
  newSqlCaller,
  systemRoles,
} from "../../../__tests__/setup.ts";
import { forgetKeyUuids } from "../../../cloud/client.ts";
import type { SqlPolicy } from "../../sql/definition.ts";
import { toSqlPolicies } from "../../sql/handler.ts";
import {
  newCommonClickHousePrimitives,
  newPolicyPrimitives,
} from "../primitives.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const readApiKey = vi.hoisted(() => vi.fn());
vi.mock("../../../secrets.ts", () => ({ readApiKey }));

vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

let cloud: FakeCloud;
let logs: ReturnType<typeof newRecordingLogger>;
let primitives: ReturnType<typeof newCommonClickHousePrimitives> &
  ReturnType<typeof newPolicyPrimitives<SqlPolicy>>;

const POLICY: SqlPolicy = {
  type: "sql",
  level: "read",
  object: {},
};

const GRANTED: FakePolicy = {
  allowDeny: "ALLOW",
  permissions: ["sql-console:database:access"],
  resources: [`instance/${SERVICE_ID}`],
  tags: { grants: ["GRANT SELECT, dictGet ON *.*"] },
};

const ROLE_PATH = new RegExp(`/organizations/${ORGANIZATION_ID}/roles/[^/]+$`);

/** P0's role for the request, as an earlier step left it. */
const seedRole = (overrides: Partial<FakeRole> = {}): FakeRole => {
  const role: FakeRole = {
    id: crypto.randomUUID(),
    name: ROLE_NAME,
    type: "custom",
    actors: [`user/${MEMBER.userId}`],
    policies: cloneDeep([...BASE_POLICIES, GRANTED]),
    ...overrides,
  };
  cloud.roles.push(role);
  return role;
};

const ours = () => cloud.roles.find(({ name }) => name === ROLE_NAME);

/** The roles listing as the fake holds it, with `extra` items and fields. */
const listingWith = (
  extra: { items?: unknown[]; page?: Record<string, unknown> } = {}
) =>
  cloud.intercept((call) =>
    isCall("GET", `/v1/organizations/${ORGANIZATION_ID}/roles`)(call)
      ? {
          status: 200,
          body: {
            status: 200,
            result: [...cloud.roles, ...(extra.items ?? [])],
            ...extra.page,
          },
        }
      : undefined
  );

/** A customer's role in a shape the connector doesn't read. */
const CUSTOMER_ROLE = {
  id: "c-odd",
  name: "analysts",
  type: "custom",
  actors: null,
  policies: [
    {
      allowDeny: "MAYBE",
      permissions: ["control-plane:service:view"],
      resources: ["instance/*"],
      tags: { grants: null, roleV2: null },
    },
  ],
};

beforeEach(() => {
  cloud = newSeededCloud();
  cloud.members.push(MEMBER);
  cloud.roles.push(...systemRoles());
  vi.stubGlobal("fetch", cloud.fetch);
  forgetKeyUuids();
  logs = newRecordingLogger();
  primitives = {
    ...newCommonClickHousePrimitives(logs.log),
    ...newPolicyPrimitives(logs.log, toSqlPolicies),
  };
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

describe("users", () => {
  it("are the requestor's email, unchanged, with nothing looked up", async () => {
    expect(await primitives.getUser(CONTEXT, "Alice@Acme.com")).toBe(
      "Alice@Acme.com"
    );
    await primitives.deleteUser();
    expect(cloud.calls).toEqual([]);
  });

  it("are never created", async () => {
    expect(
      await connectorError(() => primitives.createUser(CONTEXT, EMAIL))
    ).toMatchObject({
      type: "validation_error",
      payload: { reason: "not_member", email: EMAIL },
    });
    expect(cloud.calls).toEqual([]);
  });

  it("aren't namespaced, and roles are when they start with p0_", async () => {
    const { user, resource } = primitives.validation();
    expect(user).toBeNull();
    await expect(resource.resourceIsNamespacedById(ROLE_NAME)).resolves.toBe(
      true
    );
    await expect(resource.resourceIsNamespacedByBody("p0_x")).resolves.toBe(
      true
    );
    for (const name of ["Admin", "P0_x", "p0-x", " p0_x", ""]) {
      await expect(resource.resourceIsNamespacedById(name)).resolves.toBe(
        false
      );
      await expect(resource.resourceIsNamespacedByBody(name)).resolves.toBe(
        false
      );
    }
  });
});

describe("a role that isn't P0's", () => {
  const CALLS: [string, (name: string) => Promise<unknown>][] = [
    ["create", (name) => primitives.createResource(CONTEXT, name)],
    [
      "add a policy to",
      (name) => primitives.addPolicyToResource(CONTEXT, name, POLICY),
    ],
    [
      "remove a policy from",
      (name) => primitives.removePolicyFromResource(CONTEXT, name, POLICY),
    ],
    ["bind", (name) => primitives.bindResourceToUser(CONTEXT, name, EMAIL)],
    [
      "unbind",
      (name) => primitives.unbindResourceFromUser(CONTEXT, name, EMAIL),
    ],
    ["delete", (name) => primitives.deleteResource(CONTEXT, name)],
  ];

  it.each(CALLS)(
    "is refused as not_p0_role when asked to %s it, before any call",
    async (_what, call) => {
      cloud.roles.push({
        id: crypto.randomUUID(),
        name: "Admin",
        type: "custom",
        actors: [],
        policies: [],
      });
      const before = cloneDeep(cloud.roles);

      expect(await connectorError(() => call("Admin"))).toEqual({
        type: "validation_error",
        message:
          "P0 only changes the ClickHouse Cloud roles it created, whose names start with p0_, and Admin isn't one.",
        payload: { reason: "not_p0_role", role: "Admin" },
      });
      expect(cloud.calls).toEqual([]);
      expect(cloud.roles).toEqual(before);
    }
  );

  // The framework's own check runs first, so through the router the name is
  // refused before any primitive, with a plain error.
  it.each([
    "createAccessResource",
    "addPoliciesToResource",
    "removePoliciesFromResource",
    "bindAccessResource",
    "unbindAccessResource",
    "deleteAccessResource",
  ] as const)("is never written through the router's %s", async (route) => {
    const caller = newSqlCaller(logs.log);
    const input = {
      resourceBody: "Admin",
      resourceId: "Admin",
      userId: EMAIL,
      userBody: EMAIL,
      policies: [POLICY],
      context: CONTEXT,
    };

    await expect(caller[route](input)).rejects.toThrow("is not namespaced");
    expect(cloud.calls).toEqual([]);
  });
});

describe("createResource", () => {
  it("creates the role with the base policies and no actors, and logs the request", async () => {
    expect(await primitives.createResource(CONTEXT, ROLE_NAME)).toBe(ROLE_NAME);

    expect(cloud.writes()).toEqual([
      {
        method: "POST",
        path: `/v1/organizations/${ORGANIZATION_ID}/roles`,
        // No description: `RoleCreateRequest` has none.
        body: { name: ROLE_NAME, actors: [], policies: BASE_POLICIES },
      },
    ]);
    expect(logs.info).toHaveBeenCalledWith(
      { requestId: REQUEST_ID, description: DESCRIPTION },
      "created the role"
    );
  });

  it("reuses a role an earlier attempt created", async () => {
    seedRole({
      actors: [],
      policies: cloneDeep(BASE_POLICIES),
    });

    expect(await primitives.createResource(CONTEXT, ROLE_NAME)).toBe(ROLE_NAME);
    expect(cloud.writes()).toEqual([]);
  });

  it("fails as dependency_violation when two roles have the name, writing nothing", async () => {
    seedRole();
    seedRole();

    expect(
      await connectorError(() => primitives.createResource(CONTEXT, ROLE_NAME))
    ).toEqual({
      type: "dependency_violation",
      message: `The ClickHouse Cloud organization ${ORGANIZATION_ID} has 2 roles named ${ROLE_NAME}, so P0 can't tell which belongs to the request. Delete all but one of them in the ClickHouse Cloud console, then retry.`,
      payload: { organizationId: ORGANIZATION_ID, role: ROLE_NAME, roles: 2 },
    });
    expect(cloud.writes()).toEqual([]);
  });

  it("maps a ClickHouse Cloud failure", async () => {
    cloud.intercept((call) =>
      isCall("POST", /\/roles$/)(call) ? failing(500) : undefined
    );

    expect(
      await connectorError(() => primitives.createResource(CONTEXT, ROLE_NAME))
    ).toMatchObject({
      type: "upstream_unavailable",
      payload: { organizationId: ORGANIZATION_ID, status: 500 },
    });
  });
});

describe("addPolicyToResource", () => {
  it("sets the role's policies to the base policies plus the access's", async () => {
    seedRole({ policies: cloneDeep(BASE_POLICIES) });

    await primitives.addPolicyToResource(CONTEXT, ROLE_NAME, POLICY);

    expect(ours()?.policies).toEqual([...BASE_POLICIES, GRANTED]);
  });

  it("replaces whatever else the role held", async () => {
    seedRole({
      policies: [
        {
          allowDeny: "ALLOW",
          permissions: ["control-plane:organization:manage"],
          resources: [`organization/${ORGANIZATION_ID}`],
        },
      ],
    });

    await primitives.addPolicyToResource(CONTEXT, ROLE_NAME, POLICY);

    expect(ours()?.policies).toEqual([...BASE_POLICIES, GRANTED]);
  });

  it("writes nothing when the role already holds exactly that", async () => {
    seedRole();

    await primitives.addPolicyToResource(CONTEXT, ROLE_NAME, POLICY);

    expect(cloud.writes()).toEqual([]);
  });

  it("fails as object_not_found when the role isn't there", async () => {
    expect(
      await connectorError(() =>
        primitives.addPolicyToResource(CONTEXT, ROLE_NAME, POLICY)
      )
    ).toEqual({
      type: "object_not_found",
      message: `The ClickHouse Cloud organization ${ORGANIZATION_ID} has no role ${ROLE_NAME}, which P0 creates as it grants access. Retry the grant.`,
      payload: { organizationId: ORGANIZATION_ID, query: `role ${ROLE_NAME}` },
    });
    expect(cloud.writes()).toEqual([]);
  });
});

describe("bindResourceToUser", () => {
  const bind = (email = EMAIL) =>
    primitives.bindResourceToUser(CONTEXT, ROLE_NAME, email);

  it("makes the member with the email, ignoring case, the role's only actor", async () => {
    seedRole({ actors: ["user/someone-else"] });

    await bind("ALICE@acme.com");

    expect(ours()?.actors).toEqual([`user/${MEMBER.userId}`]);
    expect(cloud.writes()).toEqual([
      {
        method: "PATCH",
        path: expect.stringMatching(ROLE_PATH),
        body: { actors: [`user/${MEMBER.userId}`] },
      },
    ]);
  });

  it("refuses an email outside the allowed domains before any call", async () => {
    seedRole({ actors: [] });

    expect(await connectorError(() => bind("mallory@evil.com"))).toEqual({
      type: "validation_error",
      message:
        "P0 doesn't act for mallory@evil.com: the email's domain isn't one the connector's DOMAIN_ALLOW_PATTERN allows.",
      payload: { reason: "domain_not_allowed", email: "mallory@evil.com" },
    });
    expect(cloud.calls).toEqual([]);
  });

  it("refuses an email no member has, as not_member", async () => {
    seedRole({ actors: [] });

    expect(await connectorError(() => bind("bob@acme.com"))).toEqual({
      type: "validation_error",
      message: `bob@acme.com isn't a member of the ClickHouse Cloud organization ${ORGANIZATION_ID}. Join the organization, then request access again.`,
      payload: { reason: "not_member", email: "bob@acme.com" },
    });
    expect(cloud.writes()).toEqual([]);
  });

  it("refuses an email two members have, as ambiguous_member", async () => {
    seedRole({ actors: [] });
    cloud.members.push({
      ...MEMBER,
      userId: "u-2",
      email: EMAIL.toUpperCase(),
    });

    expect(await connectorError(() => bind())).toMatchObject({
      type: "validation_error",
      payload: { reason: "ambiguous_member", email: EMAIL, members: 2 },
    });
    expect(cloud.writes()).toEqual([]);
  });

  it("fails as object_not_found when the role isn't there", async () => {
    expect(await connectorError(() => bind())).toMatchObject({
      type: "object_not_found",
    });
  });

  it("writes nothing when the member is already the only actor", async () => {
    seedRole();

    await bind();

    expect(cloud.writes()).toEqual([]);
  });
});

// Every revoke step: done when the role is gone, never `object_not_found`.
const REVOKES: [string, () => Promise<void>, Partial<FakeRole> | null][] = [
  [
    "unbindResourceFromUser",
    () => primitives.unbindResourceFromUser(CONTEXT, ROLE_NAME, EMAIL),
    { actors: [] },
  ],
  [
    "removePolicyFromResource",
    () => primitives.removePolicyFromResource(CONTEXT, ROLE_NAME, POLICY),
    { policies: cloneDeep(BASE_POLICIES) },
  ],
  ["deleteResource", () => primitives.deleteResource(CONTEXT, ROLE_NAME), null],
];

describe.each(REVOKES)("%s", (_name, revoke, after) => {
  it("takes the access back", async () => {
    seedRole();

    await revoke();

    expect(ours()).toEqual(
      after === null ? undefined : expect.objectContaining(after)
    );
  });

  it("is done when the role is already gone", async () => {
    await revoke();

    expect(cloud.writes()).toEqual([]);
  });

  it("takes the access back past a customer's role it can't read", async () => {
    seedRole();
    listingWith({ items: [CUSTOMER_ROLE] });

    await revoke();

    expect(ours()).toEqual(
      after === null ? undefined : expect.objectContaining(after)
    );
  });

  // Otherwise one odd role would stop every revoke in the organization.
  it("takes the access back past another request's P0 role it can't read", async () => {
    seedRole();
    listingWith({
      items: [
        { ...CUSTOMER_ROLE, id: "p0-odd", name: "p0_cd34_bob_calm_heron" },
      ],
    });

    await revoke();

    expect(ours()).toEqual(
      after === null ? undefined : expect.objectContaining(after)
    );
  });

  it("fails when the role it acts on can't be read, writing nothing", async () => {
    listingWith({ items: [{ ...CUSTOMER_ROLE, name: ROLE_NAME }] });

    expect(await connectorError(revoke)).toMatchObject({
      type: "unknown",
      message: `ClickHouse Cloud returned the role ${ROLE_NAME} in a shape P0 doesn't recognize.`,
    });
    expect(cloud.writes()).toEqual([]);
  });

  // From a create retried after a timeout, or a name collision.
  it("takes the access back through every role with the name", async () => {
    const first = seedRole();
    const second = seedRole();

    await revoke();

    for (const { id } of [first, second]) {
      const role = cloud.roles.find((held) => held.id === id);
      expect(role).toEqual(
        after === null ? undefined : expect.objectContaining(after)
      );
    }
    expect(logs.warn).toHaveBeenCalledWith(
      { roles: 2 },
      "more than one role has the request's name; revoking through each"
    );
  });

  it.each([
    ["a next cursor", { nextCursor: "2" }],
    ["a total past what it holds", { totalCount: 99 }],
  ])(
    "fails, rather than take the role as gone, when the listing says it has more, by %s",
    async (_case, page) => {
      // The request's role on a later page.
      listingWith({ page });

      expect(await connectorError(revoke)).toMatchObject({
        type: "unknown",
        message: expect.stringContaining(
          "ClickHouse Cloud paged the roles listing"
        ),
      });
      expect(cloud.writes()).toEqual([]);
    }
  );

  it("writes nothing on a second run", async () => {
    seedRole();
    await revoke();
    const writes = cloud.writes().length;

    await revoke();

    expect(cloud.writes()).toHaveLength(writes);
  });

  // The OpenAPI documents only 400 for a role write; a 404 is taken too.
  it.each([400, 404])(
    "is done when the write gets a %s because the role just went",
    async (status) => {
      const role = seedRole();
      cloud.intercept((call) => {
        if (call.method === "GET" || !ROLE_PATH.test(call.path)) return;
        cloud.roles.splice(cloud.roles.indexOf(role), 1);
        return failing(status, "Role not found");
      });

      await revoke();

      expect(ours()).toBeUndefined();
    }
  );

  it("fails with ClickHouse Cloud's reason when the write gets a 400 and the role is still there", async () => {
    seedRole();
    cloud.intercept((call) =>
      call.method !== "GET" && ROLE_PATH.test(call.path)
        ? failing(400, "Invalid policy")
        : undefined
    );

    expect(await connectorError(revoke)).toMatchObject({
      type: "validation_error",
      message: `ClickHouse Cloud refused P0's request about role ${ROLE_NAME} (400): Invalid policy`,
    });
  });

  it("fails as it is on a 500", async () => {
    seedRole();
    cloud.intercept((call) =>
      call.method !== "GET" && ROLE_PATH.test(call.path)
        ? failing(500)
        : undefined
    );

    expect(await connectorError(revoke)).toMatchObject({
      type: "upstream_unavailable",
    });
  });
});

describe("unbindResourceFromUser", () => {
  it("isn't checked against the allowed domains", async () => {
    seedRole();

    await primitives.unbindResourceFromUser(
      CONTEXT,
      ROLE_NAME,
      "alice@acquired.example"
    );

    expect(ours()?.actors).toEqual([]);
  });
});

describe("removePolicyFromResource", () => {
  // Nobody holds it, and the delete comes next. The PATCH names the service,
  // which may be gone.
  it("leaves the policies of a role with no actors for the delete", async () => {
    seedRole({ actors: [] });

    await primitives.removePolicyFromResource(CONTEXT, ROLE_NAME, POLICY);

    expect(cloud.writes()).toEqual([]);
    expect(ours()?.policies).toEqual([...BASE_POLICIES, GRANTED]);
  });
});

describe("deleteResource", () => {
  it("says ClickHouse Cloud may take up to 10 minutes to remove the access", async () => {
    seedRole();

    await primitives.deleteResource(CONTEXT, ROLE_NAME);

    expect(logs.info).toHaveBeenCalledWith(
      "deleted the role; ClickHouse Cloud may take up to 10 minutes to remove the access it gave"
    );
  });

  it("never touches another role", async () => {
    seedRole();
    const others = cloud.roles.filter(({ name }) => name !== ROLE_NAME);

    await primitives.deleteResource(CONTEXT, ROLE_NAME);

    expect(cloud.roles).toEqual(others);
  });
});

it("logs under the request, organization, service and role", async () => {
  await primitives.deleteResource(CONTEXT, ROLE_NAME);

  expect(logs.log.child).toHaveBeenCalledWith({
    requestId: REQUEST_ID,
    organizationId: ORGANIZATION_ID,
    serviceId: SERVICE_ID,
    role: ROLE_NAME,
  });
});
