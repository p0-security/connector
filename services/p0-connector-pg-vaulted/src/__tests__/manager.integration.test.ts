import { createLogger } from "@p0security/connector-core";
import pg from "pg";
import { beforeEach, describe, expect, it } from "vitest";

import { router as roleRouter } from "../accesses/role/handler.ts";
import { router as validationRouter } from "../install/handler.ts";
import type { ManagerDependencies } from "../manager.ts";
import { connect, connectWith } from "../postgres/client.ts";
import { t } from "../router.ts";
import { dataOf, fakeSecretStore } from "./fakes.ts";

// The servers that scripts/integration-db.sh starts.
const SERVERS = [
  { version: 14, port: 54314 },
  { version: 16, port: 54316 },
];
const HOST = "127.0.0.1";

const MANAGER = { username: "it_manager", password: "it-manager-password" };
const ARN =
  "arn:aws:secretsmanager:us-east-1:123456789012:secret:it-manager-AbCdEf";
const GRANT_LOGIN = `p0v_${"a".repeat(32)}`;

/** Every role the fixture creates, the manager first so that its grants go
 * with it. */
const FIXTURE_ROLES = [
  MANAGER.username,
  "analyst",
  "reporting",
  "unshared",
  "app_login",
  "rds_superuser",
  "it_superuser",
  "Sales Team",
  "it_group",
  GRANT_LOGIN,
];

/**
 * A manager that is not superuser, set up as the README's Manager privileges
 * says, and one role for each rule a grantable role must meet: `analyst` and
 * `reporting` meet them all, and `unshared` and `it_group` are not granted to
 * the manager. Every role the manager holds `ADMIN OPTION` on but `analyst`
 * and `reporting` breaks one other rule, so that deleting any rule of the
 * predicate changes the exact list: `app_login` can log in, `it_superuser` is
 * superuser, `pg_read_all_data` and `rds_superuser` have a name the connector
 * keeps back, `Sales Team` has a name a policy cannot hold, and the grant
 * login's name is one the connector keeps back too. `pg_read_all_data` is
 * built in, so no teardown drops it: its grant goes with the manager.
 */
const FIXTURE = [
  `CREATE ROLE ${MANAGER.username} LOGIN PASSWORD '${MANAGER.password}' CREATEROLE`,
  `GRANT pg_signal_backend TO ${MANAGER.username}`,
  "CREATE ROLE analyst NOLOGIN",
  "CREATE ROLE reporting NOLOGIN",
  "CREATE ROLE unshared NOLOGIN",
  "CREATE ROLE app_login LOGIN",
  "CREATE ROLE rds_superuser NOLOGIN",
  "CREATE ROLE it_superuser NOLOGIN SUPERUSER",
  'CREATE ROLE "Sales Team" NOLOGIN',
  "CREATE ROLE it_group NOLOGIN NOINHERIT",
  `CREATE ROLE "${GRANT_LOGIN}" NOLOGIN`,
  `GRANT analyst, reporting, app_login, rds_superuser, it_superuser, pg_read_all_data, "Sales Team", "${GRANT_LOGIN}" TO ${MANAGER.username} WITH ADMIN OPTION`,
];

describe.each(SERVERS)("PostgreSQL $version", ({ version, port }) => {
  const target = {
    host: HOST,
    port,
    database: "postgres",
    managerSecretArn: ARN,
  };

  /** Runs statements as the server's superuser, and returns the last one's
   * rows. */
  const asSuperuser = async (...statements: string[]) => {
    const client = new pg.Client({
      host: HOST,
      port,
      database: "postgres",
      user: "postgres",
      password: "postgres",
    });
    await client.connect();
    try {
      let rows: unknown[] = [];
      for (const statement of statements) {
        ({ rows } = await client.query(statement));
      }
      return rows;
    } finally {
      await client.end();
    }
  };

  /** Every role and every membership, which no call may change. */
  const rolesAndMemberships = () =>
    asSuperuser(
      `SELECT r.rolname, array_agg(m.roleid::regrole::text || ' by ' || m.grantor::regrole::text ORDER BY m.roleid::regrole::text, m.grantor::regrole::text) AS memberships
        FROM pg_roles r LEFT JOIN pg_auth_members m ON m.member = r.oid
        WHERE r.rolname !~ '^pg_' GROUP BY r.rolname ORDER BY r.rolname`
    );

  const vault = fakeSecretStore({ [ARN]: JSON.stringify(MANAGER) });
  const dependencies: ManagerDependencies = {
    env: {
      MANAGER_SECRET_ARNS: JSON.stringify({
        [HOST]: { arn: ARN, targetId: "it-target" },
      }),
    },
    connectSecretManager: vault.connectSecretManager,
    connect: connectWith(false),
  };
  const logger = createLogger();

  const validate = (
    overrides: ManagerDependencies = {},
    database = target.database
  ) =>
    validationRouter(t, { ...dependencies, ...overrides })
      .createCaller({ logger })
      .get({ target: { ...target, database } });

  const list = (type: "database" | "role") =>
    roleRouter(t, dependencies)
      .createCaller({ logger })
      .list({ query: { type, context: target } });

  const GRANTABLE = ["analyst", "reporting"];

  beforeEach(async () => {
    await asSuperuser(
      ...FIXTURE_ROLES.map((role) => `DROP ROLE IF EXISTS "${role}"`),
      ...FIXTURE
    );
  });

  it("passes every check, returns exactly the grantable roles, and changes no role or membership", async () => {
    const before = await rolesAndMemberships();

    await expect(validate()).resolves.toEqual({ grantableRoles: GRANTABLE });

    expect(before).toHaveLength(FIXTURE_ROLES.length + 1);
    expect(await rolesAndMemberships()).toEqual(before);
  });

  it("lists the grantable roles and the databases", async () => {
    await expect(list("role")).resolves.toEqual(
      GRANTABLE.map((role) => ({ key: role, value: role }))
    );
    await expect(list("database")).resolves.toEqual([
      { key: "postgres", value: "postgres" },
    ]);
  });

  it("fails at create_role without CREATEROLE", async () => {
    await asSuperuser(`ALTER ROLE ${MANAGER.username} NOCREATEROLE`);

    const data = await dataOf(validate());

    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toEqual({ step: "create_role", host: HOST });
  });

  it("fails at signal_backend without pg_signal_backend", async () => {
    await asSuperuser(`REVOKE pg_signal_backend FROM ${MANAGER.username}`);

    const data = await dataOf(validate());

    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toEqual({ step: "signal_backend", host: HOST });
  });

  it.runIf(version >= 16)(
    "fails at signal_backend with a pg_signal_backend it does not inherit",
    async () => {
      await asSuperuser(
        `GRANT pg_signal_backend TO ${MANAGER.username} WITH INHERIT FALSE`
      );

      const data = await dataOf(validate());

      expect(data.payload).toEqual({ step: "signal_backend", host: HOST });
    }
  );

  // No test removes a privilege that only reassign_owned needs: on a real
  // server none exists. The manager grants itself what REASSIGN OWNED needs,
  // which the privileges of the earlier checks always allow. The next three
  // tests are the setups in which it fails without those grants.
  it.runIf(version < 16)(
    "fails at signal_backend when the manager is NOINHERIT, which also rules out the reassign",
    async () => {
      await asSuperuser(`ALTER ROLE ${MANAGER.username} NOINHERIT`);

      const data = await dataOf(validate());

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({ step: "signal_backend", host: HOST });
    }
  );

  it.runIf(version < 16)(
    "leaves out a role the manager could grant with CREATEROLE alone",
    async () => {
      await asSuperuser(`REVOKE analyst, reporting FROM ${MANAGER.username}`);

      await expect(validate()).resolves.toEqual({ grantableRoles: [] });
    }
  );

  it.runIf(version < 16)(
    "passes reassign_owned to a role whose privileges the manager does not hold",
    async () => {
      await asSuperuser(
        `REVOKE analyst, reporting FROM ${MANAGER.username}`,
        "GRANT analyst TO it_group WITH ADMIN OPTION",
        `GRANT it_group TO ${MANAGER.username}`
      );
      const before = await rolesAndMemberships();

      await expect(validate()).resolves.toEqual({
        grantableRoles: ["analyst"],
      });
      expect(await rolesAndMemberships()).toEqual(before);
    }
  );

  it.runIf(version >= 16)(
    "passes reassign_owned when the manager is NOINHERIT and holds only ADMIN OPTION on the role",
    async () => {
      await asSuperuser(
        `ALTER ROLE ${MANAGER.username} NOINHERIT`,
        `REVOKE reporting FROM ${MANAGER.username}`,
        `GRANT analyst TO ${MANAGER.username} WITH ADMIN OPTION, INHERIT FALSE, SET FALSE`
      );
      const before = await rolesAndMemberships();

      await expect(validate()).resolves.toEqual({
        grantableRoles: ["analyst"],
      });
      expect(await rolesAndMemberships()).toEqual(before);
    }
  );

  it.runIf(version >= 16)(
    "leaves out a role whose ADMIN OPTION the manager cannot use",
    async () => {
      await asSuperuser(
        `REVOKE analyst, reporting FROM ${MANAGER.username}`,
        "GRANT unshared TO reporting WITH ADMIN OPTION",
        `GRANT reporting TO ${MANAGER.username} WITH INHERIT FALSE`
      );

      await expect(validate()).resolves.toEqual({ grantableRoles: [] });
    }
  );

  it("passes with no grantable role", async () => {
    await asSuperuser("DROP ROLE analyst, reporting, unshared");
    const before = await rolesAndMemberships();

    await expect(validate()).resolves.toEqual({ grantableRoles: [] });
    expect(await rolesAndMemberships()).toEqual(before);
  });

  describe("sign_in", () => {
    it("fails as insufficient privileges with the wrong password", async () => {
      const wrong = fakeSecretStore({
        [ARN]: JSON.stringify({ ...MANAGER, password: "not-the-password" }),
      });

      const data = await dataOf(
        validate({ connectSecretManager: wrong.connectSecretManager })
      );

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({
        sqlState: "28P01",
        step: "sign_in",
        host: HOST,
      });
    });

    it("fails as not found for a database that does not exist", async () => {
      const data = await dataOf(validate({}, "no_such_database"));

      expect(data.type).toBe("object_not_found");
      expect(data.payload).toEqual({
        sqlState: "3D000",
        step: "sign_in",
        host: HOST,
      });
    });

    it("fails as unavailable, with the shipped driver, at a certificate AWS did not sign", async () => {
      const data = await dataOf(validate({ connect }));

      expect(data.type).toBe("upstream_unavailable");
      expect(data.payload).toEqual({
        code: "DEPTH_ZERO_SELF_SIGNED_CERT",
        step: "sign_in",
        host: HOST,
      });
    });
  });
});

describe("a target nothing listens on", () => {
  it("fails at sign_in as unavailable", async () => {
    const vault = fakeSecretStore({ [ARN]: JSON.stringify(MANAGER) });

    const data = await dataOf(
      validationRouter(t, {
        env: {
          MANAGER_SECRET_ARNS: JSON.stringify({
            [HOST]: { arn: ARN, targetId: "it-target" },
          }),
        },
        connectSecretManager: vault.connectSecretManager,
        connect: connectWith(false),
      })
        .createCaller({ logger: createLogger() })
        .get({
          target: {
            host: HOST,
            port: 1,
            database: "postgres",
            managerSecretArn: ARN,
          },
        })
    );

    expect(data.type).toBe("upstream_unavailable");
    expect(data.payload).toEqual({
      code: "ECONNREFUSED",
      step: "sign_in",
      host: HOST,
    });
  });
});
