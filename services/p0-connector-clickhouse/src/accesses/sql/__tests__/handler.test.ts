import { createLogger } from "@p0security/connector";
import { cloneDeep } from "lodash-es";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeCloud,
  newSeededCloud,
} from "../../../__tests__/fake-cloud.ts";
import {
  ALLOWED_PATTERN,
  KEY_ID,
  KEY_SECRET,
  ORGANIZATION_ID,
  SERVICE_ID,
} from "../../../__tests__/fixtures.ts";
import {
  BASE_POLICIES,
  CONTEXT,
  MEMBER,
  ROLE_NAME,
  grant,
  newSqlCaller,
  revoke,
  systemRoles,
  withGrant,
} from "../../../__tests__/setup.ts";
import { forgetKeyUuids } from "../../../cloud/client.ts";
import type { SqlPolicy } from "../definition.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const readApiKey = vi.hoisted(() => vi.fn());
vi.mock("../../../secrets.ts", () => ({ readApiKey }));

vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

const logger = createLogger();
logger.level = "silent";
const caller = newSqlCaller(logger);

let cloud: FakeCloud;

const ROLES = `/v1/organizations/${ORGANIZATION_ID}/roles`;

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

const sqlConsole = (grants: string[]) => ({
  allowDeny: "ALLOW",
  permissions: ["sql-console:database:access"],
  resources: [`instance/${SERVICE_ID}`],
  tags: { grants },
});

const CASES: [string, SqlPolicy, string[]][] = [
  [
    "read on the whole service",
    { type: "sql", level: "read", object: {} },
    ["GRANT SELECT, dictGet ON *.*"],
  ],
  [
    "write on the whole service, but for ClickHouse's own logs",
    { type: "sql", level: "write", object: {} },
    [
      "GRANT SELECT, dictGet, INSERT, ALTER UPDATE, ALTER DELETE, TRUNCATE ON *.*",
      "REVOKE INSERT, ALTER UPDATE, ALTER DELETE, TRUNCATE ON `system`.*",
    ],
  ],
  [
    "admin on the whole service, but for ClickHouse's own logs",
    { type: "sql", level: "admin", object: {} },
    [
      "GRANT SELECT, dictGet, INSERT, ALTER UPDATE, ALTER DELETE, TRUNCATE, CREATE, DROP, ALTER, OPTIMIZE ON *.*",
      "REVOKE INSERT, ALTER UPDATE, ALTER DELETE, TRUNCATE, CREATE, DROP, ALTER, OPTIMIZE ON `system`.*",
    ],
  ],
  [
    "write on a database",
    {
      type: "sql",
      level: "write",
      object: { database: "analytics" },
    },
    [
      "GRANT SELECT, dictGet, INSERT, ALTER UPDATE, ALTER DELETE, TRUNCATE ON `analytics`.*",
    ],
  ],
  [
    "admin on a table",
    {
      type: "sql",
      level: "admin",
      object: { database: "analytics", table: "events" },
    },
    [
      "GRANT SELECT, dictGet, INSERT, ALTER UPDATE, ALTER DELETE, TRUNCATE, CREATE, DROP, ALTER, OPTIMIZE ON `analytics`.`events`",
    ],
  ],
  [
    "read on a view, which is the view only",
    {
      type: "sql",
      level: "read",
      object: { database: "analytics", table: "v_users" },
    },
    ["GRANT SELECT, dictGet ON `analytics`.`v_users`"],
  ],
];

describe("the sql access, through its router", () => {
  it.each(CASES)(
    "grants %s, then revokes it and leaves ClickHouse Cloud as it was",
    async (_case, policy, grants) => {
      const before = cloneDeep(cloud.roles);

      await withGrant(caller, { policy }, () => {
        const role = cloud.roles.find(({ name }) => name === ROLE_NAME);
        expect(role).toEqual({
          id: expect.any(String),
          name: ROLE_NAME,
          type: "custom",
          actors: [`user/${MEMBER.userId}`],
          policies: [...BASE_POLICIES, sqlConsole(grants)],
        });
      });

      expect(cloud.roles).toEqual(before);
      const roleId = cloud.calls.find(({ method }) => method === "PATCH")?.path;
      expect(cloud.writes()).toEqual([
        {
          method: "POST",
          path: ROLES,
          body: { name: ROLE_NAME, actors: [], policies: BASE_POLICIES },
        },
        {
          method: "PATCH",
          path: roleId,
          body: { policies: [...BASE_POLICIES, sqlConsole(grants)] },
        },
        {
          method: "PATCH",
          path: roleId,
          body: { actors: [`user/${MEMBER.userId}`] },
        },
        { method: "PATCH", path: roleId, body: { actors: [] } },
        // With no actors left, the policies wait for the delete.
        { method: "DELETE", path: roleId, body: undefined },
      ]);
      // Only the role's own path is ever written.
      expect(roleId).toMatch(new RegExp(`^${ROLES}/[0-9a-f-]{36}$`));
      // The member is only ever read, never written.
      expect(
        cloud.calls
          .filter(({ path }) => path.endsWith("/members"))
          .map(({ method }) => method)
      ).toEqual(["GET"]);
    }
  );

  it("reuses the role and writes nothing more on a second grant, and on a second revoke", async () => {
    const lifecycle: { policy: SqlPolicy } = {
      policy: { type: "sql", level: "read", object: {} },
    };
    await grant(caller, lifecycle);
    const granted = cloneDeep(cloud.roles);
    const writes = cloud.writes().length;

    await grant(caller, lifecycle);
    expect(cloud.roles).toEqual(granted);
    expect(cloud.writes()).toHaveLength(writes);

    await revoke(caller, lifecycle);
    const revoked = cloud.writes().length;
    await revoke(caller, lifecycle);
    expect(cloud.writes()).toHaveLength(revoked);
    expect(cloud.roles.map(({ name }) => name)).not.toContain(ROLE_NAME);
  });

  it("refuses a table without its database before any call", async () => {
    await expect(
      caller.addPoliciesToResource({
        resourceId: ROLE_NAME,
        policies: [
          {
            type: "sql",
            level: "read",
            object: { table: "events" },
          },
        ],
        context: CONTEXT,
      })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(cloud.calls).toEqual([]);
  });

  it("refuses a level it doesn't know, and gives the role nothing", async () => {
    await expect(
      grant(caller, {
        // @ts-expect-error not a level
        policy: { type: "sql", level: "owner", object: {} },
      })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    // Only the step before, the role's creation, wrote anything.
    expect(cloud.writes().map(({ method }) => method)).toEqual(["POST"]);
  });
});
