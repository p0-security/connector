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
  newConnClient,
  newPgClient,
  newRoleLifecycle,
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

// The customer-owned role that the `role` policy grants. It carries a real
// privilege so the test can assert the grant chain actually confers access.
const SOURCE_ROLE = "test_role_source_role";
const USER_ID = "p0_role_testuser";
const RESOURCE_ID = "p0_test_role_1234";

const lifecycle = await newRoleLifecycle({
  userId: USER_ID,
  password: "password",
  resourceId: RESOURCE_ID,
  policies: [
    {
      type: "role",
      rolename: SOURCE_ROLE,
    },
  ],
  context,
});

// Whether `member` is a direct member of `group` in pg_auth_members.
const roleIsMemberOf = async (
  member: string,
  group: string
): Promise<boolean> => {
  const { rows } = await rootClient.raw<{ rows: unknown[] }>(
    `SELECT 1 FROM pg_auth_members m
     JOIN pg_roles g ON g.oid = m.roleid
     JOIN pg_roles r ON r.oid = m.member
     WHERE g.rolname = ? AND r.rolname = ? LIMIT 1`,
    [group, member]
  );
  return rows.length > 0;
};

describe.skipIf("CI" in process.env)(
  "Postgres Connector role-access Integration Test",
  () => {
    beforeAll(async () => {
      await rootClient.raw(`CREATE ROLE ??`, [SOURCE_ROLE]).catch(() => {});
      await rootClient.raw(`GRANT CREATE ON SCHEMA public TO ??`, [
        SOURCE_ROLE,
      ]);
    });

    afterAll(async () => {
      await dropRole(SOURCE_ROLE);
    });

    it("Grants the policy role to the access resource", async () => {
      await lifecycle(async () => {
        expect(
          await roleIsMemberOf(RESOURCE_ID, SOURCE_ROLE),
          "access resource should be a member of the policy's role"
        ).toBe(true);
        expect(
          await roleIsMemberOf(USER_ID, RESOURCE_ID),
          "user should be a member of the access resource"
        ).toBe(true);
      });

      // The lifecycle revokes the policy and drops the resource role on the way
      // out, so neither membership edge should survive.
      expect(await roleIsMemberOf(RESOURCE_ID, SOURCE_ROLE)).toBe(false);
      expect(await roleIsMemberOf(USER_ID, RESOURCE_ID)).toBe(false);
    });

    it("Confers the granted role's privileges to the bound user", async () => {
      await lifecycle(async () => {
        // user -> resource role -> source role; privileges flow down the chain
        // because roles inherit by default.
        const { rows } = await rootClient.raw<{
          rows: { has_priv: boolean }[];
        }>(`SELECT has_schema_privilege(?, 'public', 'CREATE') AS has_priv`, [
          USER_ID,
        ]);
        expect(
          rows[0]?.has_priv,
          "user should inherit CREATE ON SCHEMA public via the granted role"
        ).toBe(true);
      });
    });

    // A request must not widen the connector's own permissions, either by
    // granting a role to the connector's user or by granting a privileged role
    // that a bound user could then use.
    describe("Connector permission boundary", () => {
      // Stands in for `p0_iam_manager`: a login role that can create roles and
      // whose `p0` prefix passes the namespace check.
      const CONNECTOR_USER = "p0_test_iam_manager";
      const RESOURCE = "p0_test_boundary_resource";
      // A role the connector user is a member of. Granting to it would widen
      // the connector, as granting to the connector itself would.
      const GROUP_ROLE = "p0_test_connector_group";
      const LOGIN_ROLE = "test_role_login";
      const connectorContext = {
        ...context,
        db: { ...context.db, p0User: CONNECTOR_USER },
      };

      beforeAll(async () => {
        await rootClient.raw(
          `CREATE ROLE ?? WITH LOGIN CREATEROLE PASSWORD 'psqlpass'`,
          [CONNECTOR_USER]
        );
        await rootClient.raw(`CREATE ROLE ??`, [GROUP_ROLE]);
        await rootClient.raw(`GRANT ?? TO ??`, [GROUP_ROLE, CONNECTOR_USER]);
        await rootClient.raw(`CREATE ROLE ?? WITH LOGIN`, [LOGIN_ROLE]);
        await rootClient.raw(`GRANT ?? TO ?? WITH ADMIN OPTION`, [
          SOURCE_ROLE,
          CONNECTOR_USER,
        ]);
      });

      afterEach(async () => {
        await dropRole(RESOURCE);
      });

      afterAll(async () => {
        for (const role of [GROUP_ROLE, LOGIN_ROLE, CONNECTOR_USER]) {
          await dropRole(role);
        }
      });

      it("Refuses to bind an access resource to the connector's own user", async () => {
        await newConnClient().createAccessResource({
          resourceBody: RESOURCE,
          context: connectorContext,
        });

        await expect(
          newConnClient().bindAccessResource({
            userId: CONNECTOR_USER,
            userBody: CONNECTOR_USER,
            resourceId: RESOURCE,
            context: connectorContext,
          })
        ).rejects.toThrow(/connector's own identity/);

        // From PG16 the creator of a role is an admin-only member of it, so
        // check for inherited privileges rather than a membership row.
        const { rows } = await rootClient.raw<{
          rows: { inherits: boolean }[];
        }>(`SELECT pg_has_role(?, ?, 'USAGE') AS inherits`, [
          CONNECTOR_USER,
          RESOURCE,
        ]);
        expect(
          rows[0]?.inherits,
          "connector user should not inherit the access resource"
        ).toBe(false);
      });

      it("Refuses to grant a policy to the connector's own user", async () => {
        await expect(
          newConnClient().createAccessResource({
            resourceBody: CONNECTOR_USER,
            context: connectorContext,
          })
        ).rejects.toThrow(/connector's own identity/);

        await expect(
          newConnClient().addPoliciesToResource({
            resourceId: CONNECTOR_USER,
            policies: [{ type: "role", rolename: SOURCE_ROLE }],
            context: connectorContext,
          })
        ).rejects.toThrow(/connector's own identity/);
      });

      // On Cloud SQL user names are not validated, so any role the connector
      // belongs to could be named as the user.
      it("Refuses to grant to a role the connector user inherits", async () => {
        await newConnClient().createAccessResource({
          resourceBody: RESOURCE,
          context: connectorContext,
        });

        await expect(
          newConnClient().bindAccessResource({
            userId: GROUP_ROLE,
            userBody: GROUP_ROLE,
            resourceId: RESOURCE,
            context: connectorContext,
          })
        ).rejects.toThrow(/connector's own identity/);
        expect(await roleIsMemberOf(GROUP_ROLE, RESOURCE)).toBe(false);

        await expect(
          newConnClient().addPoliciesToResource({
            resourceId: GROUP_ROLE,
            policies: [{ type: "role", rolename: SOURCE_ROLE }],
            context: connectorContext,
          })
        ).rejects.toThrow(/connector's own identity/);
        expect(await roleIsMemberOf(GROUP_ROLE, SOURCE_ROLE)).toBe(false);
      });

      it("Grants a built-in role", async () => {
        await newConnClient().createAccessResource({
          resourceBody: RESOURCE,
          context,
        });
        await newConnClient().addPoliciesToResource({
          resourceId: RESOURCE,
          policies: [{ type: "role", rolename: "pg_read_all_data" }],
          context,
        });

        expect(await roleIsMemberOf(RESOURCE, "pg_read_all_data")).toBe(true);
      });

      it.each([
        ["a P0-managed role", CONNECTOR_USER],
        ["a login role", LOGIN_ROLE],
        ["a role that does not exist", "test_role_missing"],
      ])("Refuses to grant %s", async (_label, rolename) => {
        await newConnClient().createAccessResource({
          resourceBody: RESOURCE,
          context,
        });

        await expect(
          newConnClient().addPoliciesToResource({
            resourceId: RESOURCE,
            policies: [{ type: "role", rolename }],
            context,
          })
        ).rejects.toThrow(/Invalid Postgres role/);
        expect(await roleIsMemberOf(RESOURCE, rolename)).toBe(false);
      });

      it("Lists only the roles a policy may grant", async () => {
        const roles = (
          await newConnClient().list({
            query: { type: "role", context: context.db },
          })
        ).map(({ key }) => key);

        expect(roles).toContain(SOURCE_ROLE);
        expect(roles).toContain("pg_read_all_data");
        for (const role of [CONNECTOR_USER, GROUP_ROLE, LOGIN_ROLE]) {
          expect(roles).not.toContain(role);
        }
      });
    });

    describe("SQL injection resistance", () => {
      const target_role = "target_role_hacker";
      const test_role = "p0_role_inject_test_role";
      const test_user = "p0_role_testuser_inject";

      // Pre-create the target role with no privileges so a successful injection
      // is detectable via the grants it would produce.
      beforeEach(async () => {
        await rootClient.raw(`CREATE ROLE ??`, [target_role]).catch(() => {});
      });

      afterEach(async () => {
        // Sweep any `p0roleinjN` roles an injection payload may have created —
        // under either its full literal name or a truncated one — so a failing
        // run leaves no residue. Every name payload starts with `p0roleinj`.
        const { rows: stray } = await rootClient
          .raw<{
            rows: { rolname: string }[];
          }>(`SELECT rolname FROM pg_roles WHERE rolname LIKE 'p0roleinj%'`)
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

      // Whether `target_role` was granted the powerful attributes an injection would
      // try to add (CREATEROLE / CREATEDB / SUPERUSER / replication / bypassrls).
      const targetHasElevatedAttributes = async (): Promise<boolean> => {
        const { rows } = await rootClient.raw<{
          rows: { elevated: boolean }[];
        }>(
          `SELECT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls) AS elevated
           FROM pg_roles WHERE rolname = ?`,
          [target_role]
        );
        return Boolean(rows[0]?.elevated);
      };

      // Whether `target_role` is involved in ANY role-membership edge — either
      // as the group or as a member. An injected `GRANT target TO x` or
      // `GRANT x TO target` would show up here.
      const targetHasRoleMembership = async (): Promise<boolean> => {
        const { rows } = await rootClient.raw<{ rows: unknown[] }>(
          `SELECT 1 FROM pg_auth_members m
           JOIN pg_roles r ON r.oid IN (m.roleid, m.member)
           WHERE r.rolname = ? LIMIT 1`,
          [target_role]
        );
        return rows.length > 0;
      };

      it("role.rolename should not allow SQL injection", async () => {
        await newConnClient().provisionUser({ userBody: test_user, context });
        await newConnClient().createAccessResource({
          resourceBody: test_role,
          context,
        });

        // Injection attempt: terminate the intended GRANT early and redirect it
        // to target_role. Produces:
        //   GRANT "public" TO target_hacker; -- TO "p0_inject_test_role"
        const maliciousRolename = `public" TO ${target_role}; --`;

        await newConnClient()
          .addPoliciesToResource({
            resourceId: test_role,
            policies: [
              {
                type: "role",
                rolename: maliciousRolename,
              },
            ],
            context,
          })
          .catch(() => {});

        expect(
          await targetHasRoleMembership(),
          "target role gained membership — SQL injection occurred"
        ).toBe(false);
      });

      // Role/user names flow through `ident`, not knex's `??`; these exercise
      // that path end-to-end.
      it.each([
        [
          "createAccessResource (CREATE ROLE)",
          (name: string) =>
            newConnClient().createAccessResource({
              resourceBody: name,
              context,
            }),
        ],
        [
          "provisionUser (CREATE ROLE ... WITH LOGIN)",
          (name: string) =>
            newConnClient().provisionUser({ userBody: name, context }),
        ],
      ])("role/user names are not injectable via %s", async (_label, run) => {
        // Test payloads. Every payload's injected statement targets target_hacker.
        const payloads = [
          `p0roleinj1" SUPERUSER; --`,
          `p0roleinj2" CREATEROLE CREATEDB; --`,
          `p0roleinj3"; GRANT ${target_role} TO CURRENT_USER; --`,
          `p0roleinj4"; ALTER ROLE ${target_role} SUPERUSER; --`,
        ];

        for (const payload of payloads) {
          await run(payload).catch(() => {});
        }

        expect(
          await targetHasElevatedAttributes(),
          "target role gained elevated attributes — SQL injection occurred"
        ).toBe(false);

        expect(
          await targetHasRoleMembership(),
          "target role gained membership — SQL injection occurred"
        ).toBe(false);
      });
    });
  }
);
