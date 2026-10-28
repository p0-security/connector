import { describe, expect, it } from "vitest";

import {
  type GrantObject,
  LEVELS,
  LEVEL_PRIVILEGES,
  type Level,
  levelGrants,
} from "../levels.ts";
import { connectorError } from "./helpers.ts";

describe("the level table", () => {
  // Spec section 4, "Levels". The app pins its own copy to this one.
  it("is exactly the spec's", () => {
    expect(LEVEL_PRIVILEGES).toEqual({
      read: ["SELECT", "dictGet"],
      write: [
        "SELECT",
        "dictGet",
        "INSERT",
        "ALTER UPDATE",
        "ALTER DELETE",
        "TRUNCATE",
      ],
      admin: [
        "SELECT",
        "dictGet",
        "INSERT",
        "ALTER UPDATE",
        "ALTER DELETE",
        "TRUNCATE",
        "CREATE",
        "DROP",
        "ALTER",
        "OPTIMIZE",
      ],
    });
    expect(LEVELS).toEqual(["read", "write", "admin"]);
  });

  it("holds every privilege of the level below in each level", () => {
    expect(LEVEL_PRIVILEGES.write).toEqual(
      expect.arrayContaining([...LEVEL_PRIVILEGES.read])
    );
    expect(LEVEL_PRIVILEGES.admin).toEqual(
      expect.arrayContaining([...LEVEL_PRIVILEGES.write])
    );
  });

  it.each(LEVELS)(
    "gives %s no access management, grant option, system, kill, named collection or sources privilege",
    (level) => {
      const privileges = LEVEL_PRIVILEGES[level].join(" ").toUpperCase();
      for (const forbidden of [
        "ACCESS MANAGEMENT",
        "GRANT",
        "SYSTEM",
        "KILL",
        "NAMED COLLECTION",
        "SOURCES",
        "ALL",
      ]) {
        expect(privileges).not.toContain(forbidden);
      }
    }
  );
});

// Each level on each kind of object, as the exact statement `tags.grants` holds.
const TARGETS: [string, GrantObject, string][] = [
  ["the whole service", {}, "*.*"],
  ["a database", { database: "analytics" }, "`analytics`.*"],
  [
    "a table",
    { database: "analytics", table: "events" },
    "`analytics`.`events`",
  ],
  [
    "a dictionary",
    { database: "analytics", table: "countries_dict" },
    "`analytics`.`countries_dict`",
  ],
];

const PRIVILEGES: Record<Level, string> = {
  read: "SELECT, dictGet",
  write: "SELECT, dictGet, INSERT, ALTER UPDATE, ALTER DELETE, TRUNCATE",
  admin:
    "SELECT, dictGet, INSERT, ALTER UPDATE, ALTER DELETE, TRUNCATE, CREATE, DROP, ALTER, OPTIMIZE",
};

// What a whole-service request takes back on `system.*`, by level.
const SYSTEM_REVOKES: Record<Level, string[]> = {
  read: [],
  write: ["REVOKE INSERT, ALTER UPDATE, ALTER DELETE, TRUNCATE ON `system`.*"],
  admin: [
    "REVOKE INSERT, ALTER UPDATE, ALTER DELETE, TRUNCATE, CREATE, DROP, ALTER, OPTIMIZE ON `system`.*",
  ],
};

describe("levelGrants", () => {
  describe.each(LEVELS)("%s", (level) => {
    it.each(TARGETS)("on %s", (_kind, object, target) => {
      expect(levelGrants({ level, object })).toEqual([
        `GRANT ${PRIVILEGES[level]} ON ${target}`,
        ...(target === "*.*" ? SYSTEM_REVOKES[level] : []),
      ]);
    });
  });

  // So the grantee can't delete or truncate system.query_log or session_log.
  it.each(["write", "admin"] as const)(
    "takes back on system.* what %s gives beyond read, on the whole service only",
    (level) => {
      const [, revoke] = levelGrants({ level, object: {} });
      expect(revoke).toBe(SYSTEM_REVOKES[level][0]);
      for (const privilege of LEVEL_PRIVILEGES.read) {
        expect(revoke).not.toContain(` ${privilege}`);
      }
      expect(
        levelGrants({ level, object: { database: "system" } })
      ).toHaveLength(1);
    }
  );

  // A view's sources are the requestor's to request: P0 adds none.
  it("grants a view as itself only", () => {
    expect(
      levelGrants({
        level: "read",
        object: { database: "analytics", table: "v_users" },
      })
    ).toEqual([`GRANT ${PRIVILEGES.read} ON \`analytics\`.\`v_users\``]);
  });

  it("quotes every name, escaping backticks and backslashes", () => {
    expect(
      levelGrants({
        level: "read",
        object: { database: "we`ird", table: "x\\` ON *.* --" },
      })
    ).toEqual(["GRANT SELECT, dictGet ON `we\\`ird`.`x\\\\\\` ON *.* --`"]);
  });

  it("refuses a table without its database", async () => {
    expect(
      await connectorError(async () =>
        levelGrants({ level: "read", object: { table: "events" } })
      )
    ).toMatchObject({ type: "validation_error" });
  });

  it("refuses a name ClickHouse can't hold", async () => {
    expect(
      await connectorError(async () =>
        levelGrants({ level: "read", object: { database: "a\nb" } })
      )
    ).toMatchObject({ type: "validation_error" });
  });
});
