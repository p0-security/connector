import { ConnectorError, createLogger } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  AGENT,
  CONNECTOR_USER,
  PRIVILEGE_ROLE,
  fakeCatalog,
  fakeDataApi,
  install,
} from "../../__tests__/fakes.ts";
import type * as DataApiModule from "../../redshift/data-api.ts";
import { t } from "../../router.ts";
import type { ObjectsPolicy } from "../objects/definition.ts";
import { router as objectsRouter } from "../objects/handler.ts";
import { router as roleRouter } from "../role/handler.ts";

let api = fakeDataApi();

vi.mock("../../redshift/data-api.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof DataApiModule>();
  return {
    ...actual,
    newRedshiftSession: (
      ...[context, logger]: Parameters<typeof actual.newRedshiftSession>
    ) =>
      actual.newRedshiftSession(context, logger, {
        client: api.client,
        wait: async () => {},
      }),
  };
});

beforeEach(() => {
  api = fakeDataApi();
});

const roleContext = { ...install, requestId: "r1" };
const objectsContext = { ...roleContext, privilegeRole: PRIVILEGE_ROLE };

const role = () => roleRouter(t).createCaller({ logger: createLogger() });
const objects = () => objectsRouter(t).createCaller({ logger: createLogger() });

const sqls = () => api.statements.map(({ sql }) => sql);

const errorOf = async (promise: Promise<unknown>) => {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(Error);
  return error as Error;
};

const dataOf = async (promise: Promise<unknown>) => {
  const error = await errorOf(promise);
  const cause = error instanceof ConnectorError ? error : error.cause;
  expect(cause).toBeInstanceOf(ConnectorError);
  return (cause as ConnectorError).data;
};

const revokeRole = (context = roleContext) =>
  role().setPoliciesForUser({
    userId: AGENT,
    userBody: AGENT,
    policies: [],
    context,
  });

const revokeObjects = (context = objectsContext) =>
  objects().setPoliciesForUser({
    userId: AGENT,
    userBody: AGENT,
    policies: [],
    context,
  });

describe("provisionUser", () => {
  it("creates the agent's user with no password", async () => {
    const { catalog } = fakeCatalog(api);
    await expect(
      role().provisionUser({ userBody: AGENT, context: roleContext })
    ).resolves.toBe(AGENT);
    expect(sqls()).toContain(`CREATE USER "${AGENT}" PASSWORD DISABLE`);
    expect(catalog.users.has(AGENT)).toBe(true);
  });

  it("finds a user an earlier run created", async () => {
    fakeCatalog(api, { users: new Set([AGENT]) });
    await role().provisionUser({ userBody: AGENT, context: roleContext });
    expect(sqls().some((sql) => sql.startsWith("CREATE USER"))).toBe(false);
  });

  it("allows a user created after it looked", async () => {
    fakeCatalog(api);
    api.on(/FROM pg_user WHERE usename =/, () => []);
    api.on(/^CREATE USER/, () => ({
      error: `ERROR: user "${AGENT}" already exists`,
    }));
    await expect(
      role().provisionUser({ userBody: AGENT, context: roleContext })
    ).resolves.toBe(AGENT);
  });

  it.each(["IAMR:alice", "IAMR:p0-connector-redshift-ai", "p0admin"])(
    "refuses %s",
    async (user) => {
      fakeCatalog(api);
      await errorOf(
        role().provisionUser({ userBody: user, context: roleContext })
      );
      expect(api.statements).toEqual([]);
    }
  );
});

describe("role access", () => {
  it("grants each role to the agent's user", async () => {
    const { catalog } = fakeCatalog(api);
    await role().setPoliciesForUser({
      userId: AGENT,
      userBody: AGENT,
      policies: [{ role: "analyst" }, { role: "loader" }],
      context: roleContext,
    });
    expect(sqls()).toEqual([
      `GRANT ROLE "analyst" TO "${AGENT}"`,
      `GRANT ROLE "loader" TO "${AGENT}"`,
    ]);
    expect(catalog.userGrants.map(({ role }) => role)).toEqual([
      "analyst",
      "loader",
    ]);
  });

  it.each(["p0_connector_admin", "p0_agent_other", "sys:secadmin"])(
    "refuses to grant %s",
    async (name) => {
      fakeCatalog(api);
      await errorOf(
        role().setPoliciesForUser({
          userId: AGENT,
          userBody: AGENT,
          policies: [{ role: name }],
          context: roleContext,
        })
      );
      expect(api.statements).toEqual([]);
    }
  );

  it("refuses a user outside the agent namespace", async () => {
    fakeCatalog(api);
    await errorOf(
      role().setPoliciesForUser({
        userId: "IAMR:alice",
        userBody: "IAMR:alice",
        policies: [{ role: "analyst" }],
        context: roleContext,
      })
    );
    expect(api.statements).toEqual([]);
  });

  it("revokes the roles it granted, and drops only the user", async () => {
    const { catalog } = fakeCatalog(api, {
      users: new Set([AGENT]),
      userGrants: [{ role: "analyst", byConnector: true }],
    });
    await revokeRole();
    expect(catalog.userGrants).toEqual([]);
    await role().deleteUser({
      userId: AGENT,
      userBody: AGENT,
      context: roleContext,
    });
    expect(catalog.users.has(AGENT)).toBe(false);
    expect(sqls().some((sql) => sql.startsWith("DROP ROLE"))).toBe(false);
  });
});

describe("objects access", () => {
  const grant = (policies: ObjectsPolicy[]) =>
    objects().setPoliciesForUser({
      userId: AGENT,
      userBody: AGENT,
      policies,
      context: objectsContext,
    });

  it("grants a table through the privilege role, in its own database", async () => {
    const { catalog } = fakeCatalog(api);
    await grant([{ privilege: "SELECT", object: "sales.public.orders" }]);
    expect(api.statements).toEqual([
      {
        sql: `SELECT role_name FROM svv_roles WHERE role_name = '${PRIVILEGE_ROLE}'`,
        database: "dev",
      },
      { sql: `CREATE ROLE "${PRIVILEGE_ROLE}"`, database: "dev" },
      {
        sql: `GRANT USAGE ON SCHEMA "public" TO ROLE "${PRIVILEGE_ROLE}"`,
        database: "sales",
      },
      {
        sql: `GRANT SELECT ON TABLE "public"."orders" TO ROLE "${PRIVILEGE_ROLE}"`,
        database: "sales",
      },
      { sql: `GRANT ROLE "${PRIVILEGE_ROLE}" TO "${AGENT}"`, database: "dev" },
    ]);
    expect(catalog.roles.has(PRIVILEGE_ROLE)).toBe(true);
  });

  it("expands a schema, and a database to its user schemas", async () => {
    fakeCatalog(api);
    api.on("SHOW SCHEMAS FROM DATABASE", () => [
      { schema_name: "public", schema_type: "local" },
      { schema_name: "hr", schema_type: "local" },
      { schema_name: "pg_catalog", schema_type: "local" },
      { schema_name: "information_schema", schema_type: "local" },
      { schema_name: "lake", schema_type: "external" },
    ]);
    await grant([
      { privilege: "INSERT", object: "dev.public" },
      { privilege: "SELECT", object: "dev" },
    ]);
    const grants = api.statements
      .filter(({ sql }) => sql.startsWith("GRANT") && !sql.includes(' TO "'))
      .map(({ sql }) => sql);
    expect(grants).toEqual([
      `GRANT USAGE ON SCHEMA "public" TO ROLE "${PRIVILEGE_ROLE}"`,
      `GRANT INSERT ON ALL TABLES IN SCHEMA "public" TO ROLE "${PRIVILEGE_ROLE}"`,
      `GRANT SELECT ON ALL TABLES IN SCHEMA "public" TO ROLE "${PRIVILEGE_ROLE}"`,
      `GRANT USAGE ON SCHEMA "hr" TO ROLE "${PRIVILEGE_ROLE}"`,
      `GRANT SELECT ON ALL TABLES IN SCHEMA "hr" TO ROLE "${PRIVILEGE_ROLE}"`,
    ]);
  });

  it("finishes a grant that failed before the role reached the user", async () => {
    const { catalog, failOnce } = fakeCatalog(api);
    failOnce(/^GRANT ROLE/);
    const policies: ObjectsPolicy[] = [
      { privilege: "SELECT", object: "dev.public.orders" },
    ];
    await errorOf(grant(policies));
    expect(catalog.userGrants).toEqual([]);

    api.statements.length = 0;
    await grant(policies);
    expect(sqls().some((sql) => sql.startsWith("CREATE ROLE"))).toBe(false);
    expect(catalog.userGrants.map(({ role }) => role)).toEqual([
      PRIVILEGE_ROLE,
    ]);
  });

  it("refuses a privilege role outside its namespace", async () => {
    fakeCatalog(api);
    await errorOf(
      objects().setPoliciesForUser({
        userId: AGENT,
        userBody: AGENT,
        policies: [{ privilege: "SELECT", object: "dev.public.orders" }],
        context: { ...objectsContext, privilegeRole: "p0_connector_admin" },
      })
    );
    expect(api.statements).toEqual([]);
  });

  it.each(["dev.public.orders.extra", "dev..orders", 'dev."x"'])(
    "refuses the object %s",
    async (object) => {
      fakeCatalog(api);
      await errorOf(grant([{ privilege: "SELECT", object }]));
      expect(api.statements).toEqual([]);
    }
  );
});

describe("revoke", () => {
  const granted = () => ({
    users: new Set([AGENT]),
    roles: new Set([PRIVILEGE_ROLE]),
    databases: ["dev", "sales"],
    userGrants: [{ role: PRIVILEGE_ROLE, byConnector: true }],
    relationPrivileges: [
      {
        database: "sales",
        schema: "public",
        relation: "orders",
        identity: PRIVILEGE_ROLE,
        byConnector: true,
      },
    ],
    schemaPrivileges: [
      {
        database: "sales",
        schema: "public",
        identity: PRIVILEGE_ROLE,
        byConnector: true,
      },
    ],
  });

  it("empties the privilege role in each database", async () => {
    const { catalog } = fakeCatalog(api, granted());
    await revokeObjects();
    expect(catalog.userGrants).toEqual([]);
    expect(catalog.relationPrivileges).toEqual([]);
    expect(catalog.schemaPrivileges).toEqual([]);
    expect(api.statements).toContainEqual({
      sql: `REVOKE ALL ON TABLE "public"."orders" FROM ROLE "${PRIVILEGE_ROLE}"`,
      database: "sales",
    });
  });

  it.each([
    [undefined, CONNECTOR_USER],
    ["data_owner", "data_owner"],
  ])("hands the agent's tables and views to %s", async (objectOwner, owner) => {
    const { catalog } = fakeCatalog(api, {
      ...granted(),
      relations: [
        { database: "sales", schema: "public", name: "scratch" },
        { database: "dev", schema: "public", name: "v" },
        { database: "dev", schema: "public", name: "mv_tbl__mv__0" },
      ],
    });
    await revokeObjects({
      ...objectsContext,
      ...(objectOwner ? { objectOwner } : {}),
    });
    expect(api.statements).toContainEqual({
      sql: `ALTER TABLE "public"."scratch" OWNER TO "${owner}"`,
      database: "sales",
    });
    expect(api.statements).toContainEqual({
      sql: `ALTER TABLE "public"."v" OWNER TO "${owner}"`,
      database: "dev",
    });
    expect(sqls().some((sql) => sql.includes("mv_tbl__"))).toBe(false);
    expect(
      catalog.relations.filter(({ name }) => !name.startsWith("mv_tbl__"))
    ).toEqual([]);
  });

  it("drops the agent's functions, procedures and empty schemas", async () => {
    const { catalog } = fakeCatalog(api, {
      ...granted(),
      routines: [
        {
          database: "dev",
          schema: "public",
          name: "f",
          args: "integer, character varying",
          kind: "f",
        },
        { database: "dev", schema: "work", name: "p", args: "", kind: "p" },
      ],
      schemas: [{ database: "dev", name: "work", objects: 1 }],
    });
    await revokeObjects();
    expect(sqls()).toEqual(
      expect.arrayContaining([
        `DROP FUNCTION "public"."f"(integer, character varying)`,
        `DROP PROCEDURE "work"."p"()`,
        `DROP SCHEMA "work"`,
      ])
    );
    expect(catalog.routines).toEqual([]);
    expect(catalog.schemas).toEqual([]);
  });

  it("fails, listing it, when a schema the agent owns still holds tables", async () => {
    const { catalog } = fakeCatalog(api, {
      ...granted(),
      relations: [{ database: "dev", schema: "work", name: "t" }],
      schemas: [{ database: "dev", name: "work", objects: 1 }],
    });
    const data = await dataOf(revokeObjects());
    expect(data.type).toBe("dependency_violation");
    expect(data.message).toContain("dev: owns schema work, which holds 1");
    expect(catalog.relations).toEqual([]);
    expect(sqls().some((sql) => sql.startsWith("DROP SCHEMA"))).toBe(false);
  });

  it("fails, listing it, on a privilege P0 didn't grant", async () => {
    fakeCatalog(api, {
      ...granted(),
      relationPrivileges: [
        {
          database: "dev",
          schema: "hr",
          relation: "salaries",
          identity: AGENT,
          byConnector: false,
        },
      ],
    });
    const data = await dataOf(revokeObjects());
    expect(data.type).toBe("dependency_violation");
    expect(data.message).toContain(
      `dev: ${AGENT} holds a privilege on hr.salaries`
    );
  });

  it("fails when a REVOKE changed nothing", async () => {
    fakeCatalog(api, {
      ...granted(),
      schemaPrivileges: [
        {
          database: "sales",
          schema: "public",
          identity: PRIVILEGE_ROLE,
          byConnector: false,
        },
      ],
    });
    const data = await dataOf(revokeObjects());
    expect(data.message).toContain(
      `sales: ${PRIVILEGE_ROLE} holds a privilege on schema public`
    );
  });

  it.each([/^REVOKE ROLE/, /^ALTER TABLE/, /^DROP SCHEMA/])(
    "finishes on a rerun after %s failed",
    async (failing) => {
      const { catalog, failOnce } = fakeCatalog(api, {
        ...granted(),
        relations: [{ database: "dev", schema: "public", name: "t" }],
        routines: [
          { database: "dev", schema: "work", name: "p", args: "", kind: "p" },
        ],
        schemas: [{ database: "dev", name: "work", objects: 1 }],
      });
      failOnce(failing);
      await errorOf(revokeObjects());
      await revokeObjects();
      expect(catalog).toMatchObject({
        userGrants: [],
        relations: [],
        routines: [],
        schemas: [],
        relationPrivileges: [],
        schemaPrivileges: [],
      });
    }
  );

  it("refuses a user outside the agent namespace", async () => {
    fakeCatalog(api, granted());
    await errorOf(
      objects().setPoliciesForUser({
        userId: "IAMR:alice",
        userBody: "IAMR:alice",
        policies: [],
        context: objectsContext,
      })
    );
    expect(api.statements).toEqual([]);
  });
});

describe("deleteUser", () => {
  const remove = () =>
    objects().deleteUser({
      userId: AGENT,
      userBody: AGENT,
      context: objectsContext,
    });

  it("drops the user, then the privilege role", async () => {
    const { catalog } = fakeCatalog(api, {
      users: new Set([AGENT]),
      roles: new Set([PRIVILEGE_ROLE]),
    });
    await remove();
    expect(sqls()).toEqual([
      `DROP USER IF EXISTS "${AGENT}"`,
      `SELECT role_name FROM svv_roles WHERE role_name = '${PRIVILEGE_ROLE}'`,
      `DROP ROLE "${PRIVILEGE_ROLE}"`,
    ]);
    expect(catalog.users.size + catalog.roles.size).toBe(0);
  });

  it("counts a missing user and role as done", async () => {
    fakeCatalog(api);
    await remove();
    expect(sqls().some((sql) => sql.startsWith("DROP ROLE"))).toBe(false);
  });

  it("finishes on a rerun after the role drop failed", async () => {
    const { catalog, failOnce } = fakeCatalog(api, {
      users: new Set([AGENT]),
      roles: new Set([PRIVILEGE_ROLE]),
    });
    failOnce(/^DROP ROLE/);
    await errorOf(remove());
    await remove();
    expect(catalog.users.size + catalog.roles.size).toBe(0);
  });

  it("refuses a user outside the agent namespace", async () => {
    fakeCatalog(api);
    await errorOf(
      objects().deleteUser({
        userId: "IAMR:alice",
        userBody: "IAMR:alice",
        context: objectsContext,
      })
    );
    expect(api.statements).toEqual([]);
  });
});

describe("list", () => {
  it("lists through the install's target", async () => {
    api.on("SELECT role_name FROM svv_roles", () => [{ role_name: "analyst" }]);
    await expect(
      role().list({ query: { type: "role", context: install } })
    ).resolves.toEqual([{ key: "analyst", value: "analyst" }]);
    expect(api.calls[0]!.input).toMatchObject({ WorkgroupName: "analytics" });
  });
});
