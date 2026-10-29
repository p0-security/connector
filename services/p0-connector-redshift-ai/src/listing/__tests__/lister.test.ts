import { createLogger } from "@p0security/connector";
import { beforeEach, describe, expect, it } from "vitest";

import { fakeDataApi, install } from "../../__tests__/fakes.ts";
import { newRedshiftSession } from "../../redshift/data-api.ts";
import { listFor } from "../lister.ts";

const logger = createLogger();

type Database = {
  /** Schema name to whether the connector owns it. */
  schemas: Record<string, boolean>;
  /** Schemas where the connector holds `USAGE` with grant option. */
  usage?: string[];
  /** `schema.name` to whether the connector owns it. */
  relations?: Record<string, boolean>;
  /** `schema.name` to the privileges held with grant option. */
  privileges?: Record<string, string[]>;
};

let api = fakeDataApi();

beforeEach(() => {
  api = fakeDataApi();
});

/** Answers the lister's catalog reads from `databases`. */
const withCatalog = (databases: Record<string, Database>) => {
  const of = (database: unknown) => databases[database as string]!;
  api.on("SHOW DATABASES", () =>
    Object.keys(databases).map((name) => ({
      database_name: name,
      database_type: "local",
    }))
  );
  api.on(/AS owned FROM pg_namespace/, (_sql, database) =>
    Object.entries(of(database).schemas).map(([name, owned]) => ({
      name,
      owned,
    }))
  );
  api.on(/FROM svv_schema_privileges/, (_sql, database) =>
    (of(database).usage ?? []).map((name) => ({ namespace_name: name }))
  );
  api.on(/FROM pg_class/, (_sql, database) =>
    Object.entries(of(database).relations ?? {}).map(([qualified, owned]) => {
      const [schema_name, name] = qualified.split(".");
      return { schema_name: schema_name!, name: name!, owned };
    })
  );
  api.on(/FROM svv_relation_privileges/, (_sql, database) =>
    Object.entries(of(database).privileges ?? {}).flatMap(
      ([qualified, privileges]) => {
        const [namespace_name, relation_name] = qualified.split(".");
        return privileges.map((privilege_type) => ({
          namespace_name: namespace_name!,
          relation_name: relation_name!,
          privilege_type,
        }));
      }
    )
  );
};

const list = (type: "object" | "role") =>
  listFor(
    newRedshiftSession(install, logger, {
      client: api.client,
      wait: async () => {},
    }),
    logger,
    type
  );

const keys = async (type: "object" | "role") =>
  (await list(type)).map(({ key }) => key);

describe("role listing", () => {
  it("lists customer roles only", async () => {
    api.on("SELECT role_name FROM svv_roles", () =>
      [
        "sys:secadmin",
        "sys:dba",
        "p0_connector_admin",
        "p0_agent_r1",
        "loader",
        "Has Space",
        "analyst",
      ].map((role_name) => ({ role_name }))
    );
    await expect(list("role")).resolves.toEqual([
      { key: "analyst", value: "analyst" },
      { key: "loader", value: "loader" },
    ]);
  });
});

describe("object listing", () => {
  it("offers every privilege on what the connector owns, at each level", async () => {
    withCatalog({
      dev: {
        schemas: { public: true, pg_catalog: false, information_schema: false },
        relations: {
          "public.orders": true,
          "pg_catalog.pg_class": false,
          "public.mv_tbl__mv__0": false,
        },
      },
    });
    const listed = await list("object");
    expect(listed).toContainEqual({
      key: "SELECT:dev",
      value: "SELECT:dev",
      group: "Database",
    });
    expect(listed.map(({ key }) => key)).toEqual([
      "SELECT:dev",
      "INSERT:dev",
      "UPDATE:dev",
      "DELETE:dev",
      "SELECT:dev.public",
      "INSERT:dev.public",
      "UPDATE:dev.public",
      "DELETE:dev.public",
      "SELECT:dev.public.orders",
      "INSERT:dev.public.orders",
      "UPDATE:dev.public.orders",
      "DELETE:dev.public.orders",
    ]);
  });

  it("offers only the privileges held with grant option", async () => {
    withCatalog({
      dev: {
        schemas: { hr: false },
        usage: ["hr"],
        relations: { "hr.salaries": false },
        privileges: { "hr.salaries": ["SELECT", "REFERENCES"] },
      },
    });
    await expect(keys("object")).resolves.toEqual([
      "SELECT:dev",
      "SELECT:dev.hr",
      "SELECT:dev.hr.salaries",
    ]);
  });

  it("offers nothing in a schema whose USAGE it can't grant", async () => {
    withCatalog({
      dev: {
        schemas: { hr: false },
        relations: { "hr.salaries": false },
        privileges: { "hr.salaries": ["SELECT"] },
      },
    });
    await expect(keys("object")).resolves.toEqual([]);
  });

  it("offers a schema or database only when it can grant on every table in it", async () => {
    withCatalog({
      dev: {
        schemas: { public: true, hr: true },
        relations: { "public.orders": true, "hr.salaries": false },
        privileges: { "hr.salaries": ["SELECT"] },
      },
    });
    await expect(keys("object")).resolves.toEqual([
      "SELECT:dev",
      "SELECT:dev.public",
      "INSERT:dev.public",
      "UPDATE:dev.public",
      "DELETE:dev.public",
      "SELECT:dev.public.orders",
      "INSERT:dev.public.orders",
      "UPDATE:dev.public.orders",
      "DELETE:dev.public.orders",
      "SELECT:dev.hr",
      "SELECT:dev.hr.salaries",
    ]);
  });

  it("offers no database when a schema in it can't be granted, even an empty one", async () => {
    withCatalog({
      dev: {
        schemas: { public: true, locked: false },
        relations: { "public.orders": true },
      },
    });
    const listed = await keys("object");
    expect(listed).toContain("SELECT:dev.public");
    expect(listed).not.toContain("SELECT:dev");
  });

  it("lists every local database, and leaves out names it would refuse", async () => {
    withCatalog({
      dev: { schemas: { public: true }, relations: { "public.t": true } },
      sales: {
        schemas: { public: true, "Odd Schema": true },
        relations: { "public.orders": true, "public.Odd Table": true },
      },
    });
    const listed = await keys("object");
    expect(listed).toContain("SELECT:dev.public.t");
    expect(listed).toContain("SELECT:sales.public.orders");
    expect(listed.some((key) => key.includes("Odd"))).toBe(false);
    expect(
      api.statements.filter(({ sql }) => sql.includes("pg_class"))
    ).toEqual([
      expect.objectContaining({ database: "dev" }),
      expect.objectContaining({ database: "sales" }),
    ]);
  });

  it("offers no schema or database that holds no table", async () => {
    withCatalog({ dev: { schemas: { empty: true } } });
    await expect(keys("object")).resolves.toEqual([]);
  });
});
