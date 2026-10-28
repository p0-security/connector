import { createLogger } from "@p0security/connector";
import { cloneDeep } from "lodash-es";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeCloud,
  isCall,
  newSeededCloud,
} from "../../../__tests__/fake-cloud.ts";
import {
  ALLOWED_PATTERN,
  KEY_ID,
  KEY_SECRET,
  ORGANIZATION_ID,
  SERVICE_ID,
} from "../../../__tests__/fixtures.ts";
import { connectorError } from "../../../__tests__/helpers.ts";
import {
  BASE_POLICIES,
  MEMBER,
  ROLE_NAME,
  grant,
  newConsoleCaller,
  revoke,
  systemRoles,
  withGrant,
} from "../../../__tests__/setup.ts";
import { forgetKeyUuids } from "../../../cloud/client.ts";
import type { ConsolePolicy, ConsoleRole } from "../definition.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const readApiKey = vi.hoisted(() => vi.fn());
vi.mock("../../../secrets.ts", () => ({ readApiKey }));

vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

const logger = createLogger();
logger.level = "silent";
const caller = newConsoleCaller(logger);

let cloud: FakeCloud;

beforeEach(() => {
  cloud = newSeededCloud();
  cloud.members.push(MEMBER);
  cloud.roles.push(...systemRoles());
  vi.stubGlobal("fetch", cloud.fetch);
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

const INSTANCE = `instance/${SERVICE_ID}`;

/** The roles listing, with the system role in a shape the connector doesn't read. */
const unreadable = (systemRole: string) =>
  cloud.intercept((call) =>
    isCall("GET", `/v1/organizations/${ORGANIZATION_ID}/roles`)(call)
      ? {
          status: 200,
          body: {
            status: 200,
            result: cloud.roles.map((role) =>
              role.name === systemRole
                ? {
                    ...role,
                    policies: [{ ...role.policies[0], allowDeny: "MAYBE" }],
                  }
                : role
            ),
          },
        }
      : undefined
  );

const policy = (consoleRole: ConsoleRole): ConsolePolicy => ({
  type: "console",
  consoleRole,
});

// What each console role adds to the base policies.
const CASES: [ConsoleRole, unknown[]][] = [
  [
    "sql-console-readonly",
    [
      {
        allowDeny: "ALLOW",
        permissions: ["sql-console:database:access"],
        resources: [INSTANCE],
        tags: { roleV2: "sql-console-readonly" },
      },
    ],
  ],
  [
    "sql-console-admin",
    [
      {
        allowDeny: "ALLOW",
        permissions: ["sql-console:database:access"],
        resources: [INSTANCE],
        tags: { roleV2: "sql-console-admin" },
      },
    ],
  ],
  // Service Reader's control-plane:service: permissions only, on the service.
  [
    "service-reader",
    [
      {
        allowDeny: "ALLOW",
        permissions: [
          "control-plane:service:view",
          "control-plane:service:view-backups",
        ],
        resources: [INSTANCE],
      },
    ],
  ],
  // Its denials too, and each permission once.
  [
    "service-admin",
    [
      {
        allowDeny: "ALLOW",
        permissions: [
          "control-plane:service:view",
          "control-plane:service:manage",
        ],
        resources: [INSTANCE],
      },
      {
        allowDeny: "DENY",
        permissions: ["control-plane:service:delete"],
        resources: [INSTANCE],
      },
    ],
  ],
];

describe("the console access, through its router", () => {
  it.each(CASES)(
    "grants %s, then revokes it and leaves ClickHouse Cloud as it was",
    async (consoleRole, added) => {
      const before = cloneDeep(cloud.roles);

      await withGrant(caller, { policy: policy(consoleRole) }, () => {
        expect(cloud.roles.find(({ name }) => name === ROLE_NAME)).toEqual({
          id: expect.any(String),
          name: ROLE_NAME,
          type: "custom",
          actors: [`user/${MEMBER.userId}`],
          policies: [...BASE_POLICIES, ...added],
        });
      });

      expect(cloud.roles).toEqual(before);
      // Create, policies, bind, unbind, delete: with no actors left, the
      // policies wait for the delete.
      expect(cloud.writes().map(({ method }) => method)).toEqual([
        "POST",
        "PATCH",
        "PATCH",
        "PATCH",
        "DELETE",
      ]);
    }
  );

  // As ClickHouse Cloud names them (INT-669's roles listing).
  describe.each([
    ["service-reader", "Service Reader"],
    ["service-admin", "Service Admin"],
  ] as const)("%s", (consoleRole, systemRole) => {
    const addPolicy = () =>
      connectorError(async () => {
        await grant(caller, { policy: policy(consoleRole) });
      });

    it.each([systemRole.toLowerCase(), systemRole.toUpperCase()])(
      "copies the system role named %s, ignoring case",
      async (named) => {
        const found = cloud.roles.find(({ name }) => name === systemRole);
        if (found) found.name = named;
        const [, added] = CASES.find(([role]) => role === consoleRole) ?? [];

        await grant(caller, { policy: policy(consoleRole) });

        expect(
          cloud.roles.find(({ name }) => name === ROLE_NAME)?.policies
        ).toEqual([...BASE_POLICIES, ...(added ?? [])]);
      }
    );

    it("fails as dependency_violation when the system role isn't there, giving the role nothing", async () => {
      cloud.roles.splice(
        cloud.roles.findIndex(({ name }) => name === systemRole),
        1
      );

      expect(await addPolicy()).toEqual({
        type: "dependency_violation",
        message: `The ClickHouse Cloud organization ${ORGANIZATION_ID} has no system role ${systemRole}, so P0 can't copy its service permissions.`,
        payload: { organizationId: ORGANIZATION_ID, systemRole },
      });
      expect(cloud.writes().map(({ method }) => method)).toEqual(["POST"]);

      await revoke(caller, { policy: policy(consoleRole) });
      expect(cloud.roles.map(({ name }) => name)).not.toContain(ROLE_NAME);
    });

    it("fails as unknown when it can't read the system role, giving the role nothing", async () => {
      unreadable(systemRole);

      expect(await addPolicy()).toEqual({
        type: "unknown",
        message: `ClickHouse Cloud returned the role ${systemRole} in a shape P0 doesn't recognize.`,
        payload: { what: "the organization's roles" },
      });
      expect(cloud.writes().map(({ method }) => method)).toEqual(["POST"]);
    });

    it("fails as unknown when it can't read the system role in another case", async () => {
      const named = systemRole.toLowerCase();
      const found = cloud.roles.find(({ name }) => name === systemRole);
      if (found) found.name = named;
      unreadable(named);

      expect(await addPolicy()).toEqual({
        type: "unknown",
        message: `ClickHouse Cloud returned the role ${named} in a shape P0 doesn't recognize.`,
        payload: { what: "the organization's roles" },
      });
    });

    it("grants a console role that copies nothing, past the system role it can't read", async () => {
      unreadable(systemRole);

      await grant(caller, { policy: policy("sql-console-readonly") });

      expect(
        cloud.roles.find(({ name }) => name === ROLE_NAME)?.policies
      ).toHaveLength(BASE_POLICIES.length + 1);
    });

    it("doesn't take a custom role with the system role's name", async () => {
      const found = cloud.roles.find(({ name }) => name === systemRole);
      if (found) found.type = "custom";

      expect(await addPolicy()).toMatchObject({
        type: "dependency_violation",
      });
    });

    it("fails as dependency_violation when the system role gives no service permission", async () => {
      const found = cloud.roles.find(({ name }) => name === systemRole);
      if (found) {
        found.policies = [
          {
            allowDeny: "ALLOW",
            permissions: [
              "sql-console:database:access",
              "control-plane:organization:view",
            ],
            resources: ["instance/*"],
          },
        ];
      }

      expect(await addPolicy()).toMatchObject({
        type: "dependency_violation",
        message: `The ClickHouse Cloud organization ${ORGANIZATION_ID} has a system role ${systemRole} that gives no service permission, so P0 can't copy its service permissions.`,
      });
      expect(cloud.writes().map(({ method }) => method)).toEqual(["POST"]);
    });

    it("fails as dependency_violation when two system roles have the name", async () => {
      const found = cloud.roles.find(({ name }) => name === systemRole);
      if (found) {
        cloud.roles.push({ ...cloneDeep(found), id: crypto.randomUUID() });
      }

      expect(await addPolicy()).toMatchObject({
        type: "dependency_violation",
        payload: { systemRole },
      });
    });
  });

  it("refuses a console role it doesn't know", async () => {
    await expect(
      grant(caller, {
        // @ts-expect-error not a console role
        policy: { type: "console", consoleRole: "org-admin" },
      })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });
});
