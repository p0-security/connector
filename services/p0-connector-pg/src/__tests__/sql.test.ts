import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from "vitest";

import {
  PG_DATABASE,
  PG_HOST,
  PG_PORT,
  PG_USER,
  dropRole,
  newPgClient,
  newSqlConnClient,
  newSqlLifecycle,
} from "./setup.ts";

const context = {
  requestId: "test-request-id",
  db: {
    host: PG_HOST,
    database: PG_DATABASE,
    port: PG_PORT,
    p0User: PG_USER,
    cloud: "localhost" as const,
  },
};

const rootClient = newPgClient();

const USER_ID = "p0_sql_testuser";
const SCHEMA_RESOURCE_ID = "p0_test_schema_priv_1234";
const TABLE_RESOURCE_ID = "p0_test_table_priv_1234";
const QUALIFIED_TABLE_RESOURCE_ID = "p0_test_qualified_table_priv_1234";
// Table the table-privilege policy grants on.
const GRANT_TABLE = "test_grant_table";

const schemaLifecycle = await newSqlLifecycle({
  userId: USER_ID,
  password: "password",
  resourceId: SCHEMA_RESOURCE_ID,
  policies: [
    {
      type: "schema-privilege",
      schema: "public",
      privilege: "CREATE",
    },
  ],
  context,
});

const tableLifecycle = await newSqlLifecycle({
  userId: USER_ID,
  password: "password",
  resourceId: TABLE_RESOURCE_ID,
  policies: [
    {
      type: "table-privilege",
      table: GRANT_TABLE,
      privilege: "SELECT",
    },
  ],
  context,
});

// The shape the backend always sends: the schema is resolved before the policy
// is built, so the target arrives qualified.
const qualifiedTableLifecycle = await newSqlLifecycle({
  userId: USER_ID,
  password: "password",
  resourceId: QUALIFIED_TABLE_RESOURCE_ID,
  policies: [
    {
      type: "table-privilege",
      table: `public.${GRANT_TABLE}`,
      privilege: "SELECT",
    },
  ],
  context,
});

describe.skipIf("CI" in process.env)(
  "Postgres Connector sql-access Integration Test",
  () => {
    it("Grants Schema privileges", async () => {
      await schemaLifecycle(async (testClient) => {
        const tableName = `test_table`;
        await testClient.schema.createTable(tableName, (table) => {
          table.increments("id");
          table.string("name");
        });
        await testClient.schema.dropTable(tableName);

        // user -> resource role -> granted privilege; privileges flow down the
        // chain because roles inherit by default.
        const { rows } = await rootClient.raw<{
          rows: { has_priv: boolean }[];
        }>(`SELECT has_schema_privilege(?, 'public', 'CREATE') AS has_priv`, [
          USER_ID,
        ]);
        expect(
          rows[0]?.has_priv,
          "user should inherit CREATE ON SCHEMA public via the access resource"
        ).toBe(true);
      });
    });

    describe("Table privileges", () => {
      beforeAll(async () => {
        await rootClient.raw(`CREATE TABLE IF NOT EXISTS ?? (id int)`, [
          GRANT_TABLE,
        ]);
      });

      afterAll(async () => {
        await rootClient.raw(`DROP TABLE IF EXISTS ??`, [GRANT_TABLE]);
      });

      it("Grants Table privileges", async () => {
        await tableLifecycle(async () => {
          const { rows } = await rootClient.raw<{
            rows: { has_priv: boolean }[];
          }>(`SELECT has_table_privilege(?, ?, 'SELECT') AS has_priv`, [
            USER_ID,
            GRANT_TABLE,
          ]);
          expect(
            rows[0]?.has_priv,
            "user should inherit SELECT on the table via the access resource"
          ).toBe(true);
        });
      });

      it("Grants Table privileges on a schema-qualified table", async () => {
        await qualifiedTableLifecycle(async () => {
          const { rows } = await rootClient.raw<{
            rows: { has_priv: boolean }[];
          }>(`SELECT has_table_privilege(?, ?, 'SELECT') AS has_priv`, [
            USER_ID,
            GRANT_TABLE,
          ]);
          expect(
            rows[0]?.has_priv,
            "user should inherit SELECT on the qualified table via the access resource"
          ).toBe(true);
        });
      });

      // A wildcard would grant every table in the schema; SQL-text access only
      // ever needs the concrete relations a query touches.
      it("Refuses a schema wildcard target", async () => {
        await newSqlConnClient().createAccessResource({
          resourceBody: TABLE_RESOURCE_ID,
          context,
        });

        await expect(
          newSqlConnClient().addPoliciesToResource({
            resourceId: TABLE_RESOURCE_ID,
            policies: [
              {
                type: "table-privilege",
                table: "public.*",
                privilege: "SELECT",
              },
            ],
            context,
          })
        ).rejects.toThrow(/Invalid Postgres table/);

        const { rows } = await rootClient.raw<{
          rows: { has_priv: boolean }[];
        }>(`SELECT has_table_privilege(?, ?, 'SELECT') AS has_priv`, [
          TABLE_RESOURCE_ID,
          GRANT_TABLE,
        ]);
        expect(rows[0]?.has_priv, "no privilege should have been granted").toBe(
          false
        );

        await newSqlConnClient().deleteAccessResource({
          resourceId: TABLE_RESOURCE_ID,
          context,
        });
      });
    });

    // The role policy shares its guard with the role access type; this checks
    // that the sql access type applies it too.
    it("Refuses to grant a login role", async () => {
      const loginRole = "test_sql_login_role";
      await rootClient.raw(`CREATE ROLE ?? WITH LOGIN`, [loginRole]);
      await newSqlConnClient().createAccessResource({
        resourceBody: SCHEMA_RESOURCE_ID,
        context,
      });

      try {
        await expect(
          newSqlConnClient().addPoliciesToResource({
            resourceId: SCHEMA_RESOURCE_ID,
            policies: [{ type: "role", rolename: loginRole }],
            context,
          })
        ).rejects.toThrow(/Invalid Postgres role/);

        const { rows } = await rootClient.raw<{
          rows: { is_member: boolean }[];
        }>(`SELECT pg_has_role(?, ?, 'MEMBER') AS is_member`, [
          SCHEMA_RESOURCE_ID,
          loginRole,
        ]);
        expect(rows[0]?.is_member, "no role should have been granted").toBe(
          false
        );
      } finally {
        await newSqlConnClient().deleteAccessResource({
          resourceId: SCHEMA_RESOURCE_ID,
          context,
        });
        await dropRole(loginRole);
      }
    });

    describe("SQL injection resistance", () => {
      const target_role = "target_sql_hacker";
      const test_role = "p0_sql_inject_test_role";
      const test_user = "p0_sql_testuser_inject";

      // Pre-create the target role with no privileges so a successful injection
      // is detectable via the grants it would produce.
      beforeEach(async () => {
        await rootClient.raw(`CREATE ROLE ??`, [target_role]).catch(() => {});
      });

      afterEach(async () => {
        // Sweep any `p0sqlinjN` roles an injection payload may have created —
        // under either its full literal name or a truncated one — so a failing
        // run leaves no residue. Every name payload starts with `p0sqlinj`.
        const { rows: stray } = await rootClient
          .raw<{
            rows: { rolname: string }[];
          }>(`SELECT rolname FROM pg_roles WHERE rolname LIKE 'p0sqlinj%'`)
          .catch(() => ({ rows: [] }));

        for (const role of [
          target_role,
          test_role,
          test_user,
          ...stray.map((r) => r.rolname),
        ]) {
          await dropRole(role);
        }
      });

      // Check whether the injected role received any schema or table privileges.
      const injectedRoleHasPrivileges = async (): Promise<boolean> => {
        // Schema privileges live in pg_namespace ACLs; has_schema_privilege is
        // the cleanest way to check them without parsing aclitem arrays.
        const { rows: schemaCheck } = await rootClient.raw<{
          rows: { has_priv: boolean }[];
        }>(`SELECT has_schema_privilege(?, 'public', 'CREATE') AS has_priv`, [
          target_role,
        ]);
        if (schemaCheck[0]?.has_priv) return true;

        // Table privileges are exposed via information_schema.role_table_grants
        const { rows: tableCheck } = await rootClient.raw<{ rows: unknown[] }>(
          `SELECT 1 FROM information_schema.role_table_grants WHERE grantee = ? LIMIT 1`,
          [target_role]
        );
        return tableCheck.length > 0;
      };

      it("schema-privilege.privilege should not allow SQL injection", async () => {
        await newSqlConnClient().provisionUser({
          userBody: test_user,
          context,
        });
        await newSqlConnClient().createAccessResource({
          resourceBody: test_role,
          context,
        });

        // Injection attempt: terminate the intended GRANT early and redirect it
        // to target_role. The privilege is the one fragment interpolated as a
        // keyword rather than quoted, so the allowlist has to reject this
        // outright — nothing downstream would.
        const maliciousPrivilege = `CREATE ON SCHEMA public TO ${target_role}; --`;

        await newSqlConnClient()
          .addPoliciesToResource({
            resourceId: test_role,
            policies: [
              {
                type: "schema-privilege",
                privilege: maliciousPrivilege,
                schema: "public",
              },
            ],
            context,
          })
          .catch(() => {});

        expect(
          await injectedRoleHasPrivileges(),
          "Injected role must not have privileges — SQL injection occurred"
        ).toBe(false);
      });

      it("table-privilege.privilege should not allow SQL injection", async () => {
        await newSqlConnClient().provisionUser({
          userBody: test_user,
          context,
        });
        await newSqlConnClient().createAccessResource({
          resourceBody: test_role,
          context,
        });

        // Injection attempt: comment out the intended ON TABLE clause and
        // redirect to target_role via a schema GRANT. As above, the privilege
        // allowlist is the only guard on this fragment.
        const maliciousPrivilege = `CREATE ON SCHEMA public TO ${target_role}; --`;

        await newSqlConnClient()
          .addPoliciesToResource({
            resourceId: test_role,
            policies: [
              {
                type: "table-privilege",
                privilege: maliciousPrivilege,
                table: "pg_tables",
              },
            ],
            context,
          })
          .catch(() => {});

        expect(
          await injectedRoleHasPrivileges(),
          "Injected role must not have privileges — SQL injection occurred"
        ).toBe(false);
      });

      // Role/user names flow through `ident`, not knex's `??`; these exercise
      // that path end-to-end on the sql-access router.
      it.each([
        [
          "createAccessResource (CREATE ROLE)",
          (name: string) =>
            newSqlConnClient().createAccessResource({
              resourceBody: name,
              context,
            }),
        ],
        [
          "provisionUser (CREATE ROLE ... WITH LOGIN)",
          (name: string) =>
            newSqlConnClient().provisionUser({ userBody: name, context }),
        ],
      ])("role/user names are not injectable via %s", async (_label, run) => {
        const payloads = [
          `p0sqlinj1" SUPERUSER; --`,
          `p0sqlinj2" CREATEROLE CREATEDB; --`,
          `p0sqlinj3"; GRANT ${target_role} TO CURRENT_USER; --`,
          `p0sqlinj4"; ALTER ROLE ${target_role} SUPERUSER; --`,
        ];

        for (const payload of payloads) {
          await run(payload).catch(() => {});
        }

        const { rows } = await rootClient.raw<{
          rows: { elevated: boolean }[];
        }>(
          `SELECT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls) AS elevated
           FROM pg_roles WHERE rolname = ?`,
          [target_role]
        );
        expect(
          Boolean(rows[0]?.elevated),
          "target role gained elevated attributes — SQL injection occurred"
        ).toBe(false);

        expect(
          await injectedRoleHasPrivileges(),
          "Injected role must not have privileges — SQL injection occurred"
        ).toBe(false);
      });
    });
  }
);
