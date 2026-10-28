import { describe, expect, it } from "vitest";

import { KEY_UUID } from "../../__tests__/fixtures.ts";
import { isP0Name } from "../../namespace.ts";
import {
  P0_ENDPOINTS,
  P0_ENDPOINT_NAMES,
  endpointRequest,
  isCurrent,
  matchesListed,
} from "../endpoints.ts";

const OTHER_KEY = "0a9b8c7d-6e5f-4a3b-9c2d-1e0f9a8b7c6d";

const current = (name: (typeof P0_ENDPOINT_NAMES)[number]) => {
  const { sql, parameters } = P0_ENDPOINTS[name];
  return {
    id: "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
    name,
    sql,
    parameters,
    database: "system",
    apiKeyIds: [KEY_UUID],
    roles: ["sql_console_read_only"],
    allowedOrigins: [],
    url: "https://queries.clickhouse.cloud/run/1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
  };
};

describe("P0's endpoints", () => {
  it("are the one the spec names", () => {
    expect(P0_ENDPOINT_NAMES).toEqual(["p0_objects"]);
    expect(Object.keys(P0_ENDPOINTS).sort()).toEqual(
      [...P0_ENDPOINT_NAMES].sort()
    );
  });

  it("are each named under P0's prefix, by their own key", () => {
    for (const name of P0_ENDPOINT_NAMES) {
      expect(P0_ENDPOINTS[name].name).toBe(name);
      expect(isP0Name(name)).toBe(true);
    }
  });

  it("leave ClickHouse's own databases out of the objects", () => {
    const { sql } = P0_ENDPOINTS.p0_objects;
    expect(sql).toContain(
      "database NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema')"
    );
    expect(sql).toContain("position(database, '.') = 0");
    expect(sql).toContain("engine != 'Dictionary'");
    expect(sql).toContain("NOT is_temporary");
    expect(sql).toContain("'.inner.'");
    expect(sql).toContain("'.inner_id.'");
  });

  // In one `SELECT`, `'' AS name` would also stand for `name` in
  // `name AS database`, and every database would come back as "".
  it("name the databases in a subquery of their own", () => {
    expect(P0_ENDPOINTS.p0_objects.sql).toContain(
      "SELECT database, '' AS name, 'database' AS kind FROM (SELECT name AS database FROM system.databases)"
    );
  });

  it("have no default parameters and no statement separators", () => {
    for (const name of P0_ENDPOINT_NAMES) {
      expect(P0_ENDPOINTS[name].parameters).toEqual({});
      expect(P0_ENDPOINTS[name].sql).not.toContain(";");
    }
  });
});

describe("endpointRequest", () => {
  it("is the definition, run as SQL console's read-only role, by the key alone, with no CORS origins", () => {
    expect(endpointRequest(P0_ENDPOINTS.p0_objects, KEY_UUID)).toEqual({
      name: "p0_objects",
      sql: P0_ENDPOINTS.p0_objects.sql,
      database: "system",
      parameters: {},
      apiKeyIds: [KEY_UUID],
      roles: ["sql_console_read_only"],
      allowedOrigins: [],
    });
  });

  it("gives each request its own role list", () => {
    const first = endpointRequest(P0_ENDPOINTS.p0_objects, KEY_UUID);
    first.roles.push("sql_console_admin");

    expect(endpointRequest(P0_ENDPOINTS.p0_objects, KEY_UUID).roles).toEqual([
      "sql_console_read_only",
    ]);
  });
});

describe("isCurrent", () => {
  it("holds for exactly the definition and the key", () => {
    expect(
      isCurrent(current("p0_objects"), P0_ENDPOINTS.p0_objects, KEY_UUID)
    ).toBe(true);
  });

  it("ignores the key ID's case and the SQL's surrounding whitespace", () => {
    const endpoint = {
      ...current("p0_objects"),
      apiKeyIds: [KEY_UUID.toUpperCase()],
      sql: ` ${P0_ENDPOINTS.p0_objects.sql}\n`,
    };

    expect(isCurrent(endpoint, P0_ENDPOINTS.p0_objects, KEY_UUID)).toBe(true);
  });

  it.each([
    ["another SQL", { sql: "SELECT 2" }],
    ["another database", { database: "default" }],
    ["default parameters", { parameters: { database: "x" } }],
    ["the admin role", { roles: ["sql_console_admin"] }],
    [
      "another role too",
      { roles: ["sql_console_read_only", "sql_console_admin"] },
    ],
    ["another key only, after a rotation", { apiKeyIds: [OTHER_KEY] }],
    ["another key too", { apiKeyIds: [KEY_UUID, OTHER_KEY] }],
    ["no key", { apiKeyIds: [] }],
    ["a CORS origin", { allowedOrigins: ["https://evil.example"] }],
    ["another name", { name: "p0_tables" }],
  ])("doesn't hold with %s", (_case, change) => {
    expect(
      isCurrent(
        { ...current("p0_objects"), ...change },
        P0_ENDPOINTS.p0_objects,
        KEY_UUID
      )
    ).toBe(false);
  });
});

describe("matchesListed", () => {
  it("checks what a listing shows, without the SQL", () => {
    const {
      sql: _sql,
      parameters: _parameters,
      ...listed
    } = current("p0_objects");

    expect(matchesListed(listed, KEY_UUID)).toBe(true);
    expect(matchesListed({ ...listed, apiKeyIds: [OTHER_KEY] }, KEY_UUID)).toBe(
      false
    );
  });
});
