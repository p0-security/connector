import knex from "knex";
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
  MYSQL_HOST,
  MYSQL_PASS,
  MYSQL_PORT,
  MYSQL_USER,
  newConnClient,
  newLifecycle,
} from "./setup.ts";

const context = {
  requestId: "test-request-id",
  db: {
    host: MYSQL_HOST,
    port: MYSQL_PORT,
    p0User: MYSQL_USER,
    cloud: "localhost" as const,
  },
};

const newClient = (user: string, password: string, database?: string) =>
  knex({
    client: "mysql2",
    connection: {
      host: "localhost",
      user,
      password,
      database: database ?? "sys",
    },
  });
const rootClient = newClient(MYSQL_USER, MYSQL_PASS);

const roleExists = async (role: string): Promise<boolean> => {
  const res = await rootClient.raw(
    "SELECT User FROM mysql.user WHERE User = ?",
    [role]
  );
  return res[0].length > 0;
};

const loginAs = async (args: {
  user: string;
  password: string;
  role: string;
  database?: string;
}) => {
  const { user, password, role, database } = args;
  await rootClient.raw("ALTER USER ?? IDENTIFIED BY ?", [user, password]);
  const client = newClient(user, password, database);
  await client.raw(`SET ROLE ${role};`);
  return client;
};

const test_user = "p0_testuser";
const test_role = "p0_testrole";
const existing_role = "some_role";
const existing_table = "test_table";
const created_table = "test_table2";
const test_password = "newpassword12!";

const cleanup = async () => {
  for (const role of [test_role, test_user, existing_role]) {
    await rootClient.raw(`DROP ROLE IF EXISTS ??`, [role]);
  }

  for (const table of [existing_table, created_table]) {
    if (await rootClient.schema.hasTable(table)) {
      await rootClient.schema.dropTable(table);
    }
  }
};

describe.skipIf("CI" in process.env)("MySQL Connector Integration Test", () => {
  beforeAll(async () => {
    await cleanup();

    await rootClient.schema.createTable(existing_table, (table) => {
      table.increments("id");
      table.string("name");
    });

    await rootClient.raw(`CREATE ROLE ??`, [existing_role]);
    await rootClient.raw(`GRANT INSERT ON ?? TO ??`, [
      existing_table,
      existing_role,
    ]);
  });

  afterAll(async () => {
    await cleanup();
  });

  it("Creates a user and role that can be logged in with", async () => {
    await newConnClient().provisionUser({ userBody: test_user, context });
    await expect(roleExists(test_user)).resolves.toBe(true);

    await newConnClient().createAccessResource({
      resourceBody: test_role,
      context,
    });
    await expect(roleExists(test_role)).resolves.toBe(true);

    await newConnClient().addPoliciesToResource({
      resourceId: test_role,
      policies: [],
      context,
    });

    await newConnClient().bindAccessResource({
      resourceId: test_role,
      userId: test_user,
      userBody: test_user,
      context,
    });

    const testClient = await loginAs({
      user: test_user,
      password: test_password,
      role: test_role,
      database: "",
    });
    await expect(testClient.raw("SELECT 1")).resolves.not.toThrow();
    await expect(
      testClient.raw("SET ROLE ??", [test_role])
    ).resolves.not.toThrow();

    await newConnClient().unbindAccessResource({
      resourceId: test_role,
      userId: test_user,
      userBody: test_user,
      context,
    });

    await newConnClient().removePoliciesFromResource({
      resourceId: test_role,
      policies: [],
      context,
    });

    await newConnClient().deleteAccessResource({
      resourceId: test_role,
      context,
    });
    await expect(roleExists(test_role)).resolves.toBe(false);
    await expect(roleExists(test_user)).resolves.toBe(true);
  });

  it("Grants role privileges", async () => {
    const lifecycle = await newLifecycle({
      userId: test_user,
      password: test_password,
      resourceId: test_role,
      context,
      policies: [
        {
          type: "role" as const,
          rolename: "some_role",
        },
      ],
    });

    await lifecycle(async (testClient) => {
      await expect(
        rootClient.select("*").from(existing_table).where({ name: "test" })
      ).resolves.toHaveLength(0);
      await expect(
        testClient.insert({ name: "test" }).into(existing_table)
      ).resolves.not.toThrow();
      await expect(
        rootClient.select("*").from(existing_table).where({ name: "test" })
      ).resolves.toHaveLength(1);
    });
  });

  it("Grants schema privileges", async () => {
    const lifecycle = await newLifecycle({
      userId: test_user,
      password: test_password,
      resourceId: test_role,
      context,
      policies: [
        {
          type: "schema-privilege" as const,
          privilege: "CREATE",
          schema: "sys",
        },
        {
          type: "schema-privilege" as const,
          privilege: "DROP",
          schema: "sys",
        },
      ],
    });

    await lifecycle(async (testClient) => {
      await expect(
        testClient.schema.createTable(created_table, (table) => {
          table.increments("id");
          table.string("name");
        })
      ).resolves.not.toThrow();
      await expect(rootClient.schema.hasTable(created_table)).resolves.toBe(
        true
      );

      await expect(
        testClient.schema.dropTable(created_table)
      ).resolves.not.toThrow();
      await expect(rootClient.schema.hasTable(created_table)).resolves.toBe(
        false
      );
    });
  });

  it("Grants table privileges", async () => {
    const lifecycle = await newLifecycle({
      userId: test_user,
      password: test_password,
      resourceId: test_role,
      context,
      policies: [
        {
          type: "table-privilege" as const,
          privilege: "SELECT",
          schema: "sys",
          table: existing_table,
        },
        {
          type: "table-privilege" as const,
          privilege: "UPDATE",
          schema: "sys",
          table: existing_table,
        },
      ],
    });

    await lifecycle(async (testClient) => {
      await expect(
        rootClient
          .select("*")
          .from(existing_table)
          .where({ name: "test_updated" })
      ).resolves.toHaveLength(0);
      await expect(
        testClient
          .table(existing_table)
          .update({ name: "test_updated" })
          .where({ name: "test" })
      ).resolves.not.toThrow();

      await expect(
        rootClient
          .select("*")
          .from(existing_table)
          .where({ name: "test_updated" })
      ).resolves.toHaveLength(1);
    });
  });

  describe("SQL injection resistance", () => {
    const target_user = "target_hacker";

    // MySQL 8 does not auto-create users on GRANT, so the target user must exist
    // for the injection to succeed. We pre-create it with no privileges so that a
    // successful injection is detectable via its resulting grants.
    beforeEach(async () => {
      await rootClient.raw(`CREATE USER IF NOT EXISTS ??@??`, [
        target_user,
        "%",
      ]);
    });

    afterEach(async () => {
      await rootClient.raw(`DROP USER IF EXISTS ??@??`, [target_user, "%"]);
      await rootClient.raw(`DROP ROLE IF EXISTS ??`, [test_role]);
    });

    const injectedUserHasGlobalPrivileges = async (): Promise<boolean> => {
      const [rows] = await rootClient.raw<[{ PRIVILEGE_TYPE: string }[]]>(
        `SELECT PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES
         WHERE GRANTEE = CONCAT("'", ?, "'@'", ?, "'")
           AND PRIVILEGE_TYPE != 'USAGE'`,
        [target_user, "%"]
      );
      return rows.length > 0;
    };

    it("schema-privilege.privilege should not allow SQL injection", async () => {
      await newConnClient().provisionUser({ userBody: test_user, context });
      await newConnClient().createAccessResource({
        resourceBody: test_role,
        context,
      });

      // Injection attempt: comment out the intended target and redirect the GRANT
      // to target_user. Produces:
      //   GRANT ALL PRIVILEGES ON *.* TO 'target_hacker'@'%' -- ON `sys`.* TO `p0_testrole`
      const maliciousPrivilege = `ALL PRIVILEGES ON *.* TO '${target_user}'@'%' -- `;

      await newConnClient()
        .addPoliciesToResource({
          resourceId: test_role,
          policies: [
            {
              type: "schema-privilege",
              // @ts-expect-error intentionally passing in input that does not satisfy type requirements as part of the test
              privilege: maliciousPrivilege,
              schema: "sys",
            },
          ],
          context,
        })
        .catch(() => {});

      expect(
        await injectedUserHasGlobalPrivileges(),
        "Injected user must not have global privileges — SQL injection occurred"
      ).toBe(false);
    });

    it("table-privilege.privilege should not allow SQL injection", async () => {
      await newConnClient().provisionUser({ userBody: test_user, context });
      await newConnClient().createAccessResource({
        resourceBody: test_role,
        context,
      });

      const maliciousPrivilege = `ALL PRIVILEGES ON *.* TO '${target_user}'@'%' -- `;

      await newConnClient()
        .addPoliciesToResource({
          resourceId: test_role,
          policies: [
            {
              type: "table-privilege",
              // @ts-expect-error intentionally passing in input that does not satisfy type requirements as part of the test
              privilege: maliciousPrivilege,
              schema: "sys",
              table: existing_table,
            },
          ],
          context,
        })
        .catch(() => {});

      expect(
        await injectedUserHasGlobalPrivileges(),
        "Injected user must not have global privileges — SQL injection occurred"
      ).toBe(false);
    });
  });
});
