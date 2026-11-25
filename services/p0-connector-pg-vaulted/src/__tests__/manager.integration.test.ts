import { createLogger } from "@p0security/connector-core";
import knex, { type Knex } from "knex";
import pg from "pg";
import { beforeEach, describe, expect, it } from "vitest";

import { listGrantableRoles } from "../accesses/common/handler.ts";
import { type ClientDependencies, newClient } from "../dbclient.ts";
import { router as validationRouter } from "../install/handler.ts";
import { t } from "../router.ts";
import { dataOf, fakeSecretStore } from "./fakes.ts";
import { PG_PASS, PG_USER } from "./setup.ts";

// The servers that scripts/integration-db.sh starts.
const SERVERS = [
  { version: 14, port: 54314 },
  { version: 16, port: 54316 },
];
const HOST = "127.0.0.1";

const MANAGER = { username: "it_manager", password: "it-manager-password" };
const MANAGER_SECRET =
  "p0/install/postgres/vpc-0a1b2c3d4e5f67890/it-target/p0manager";
const CONNECTOR_ENV = { AWS_REGION: "us-east-1" };
const GRANT_LOGIN = `p0v_${"a".repeat(32)}`;

/** The RDS client with TLS turned off, which the local servers' self-signed
 * certificates need. Only a test can build it: no request can. */
const withoutTls = (config: Knex.Config) =>
  knex({
    ...config,
    connection: {
      ...(config.connection as Knex.PgConnectionConfig),
      ssl: false,
    },
  });

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
 * login's name starts with `p0`, which the connector keeps back too. `pg_read_all_data` is
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
    managerSecret: MANAGER_SECRET,
  };

  /** Runs statements as the server's superuser, and returns the last one's
   * rows. */
  const asSuperuser = async (...statements: string[]) => {
    const client = new pg.Client({
      host: HOST,
      port,
      database: "postgres",
      user: PG_USER,
      password: PG_PASS,
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

  const vault = fakeSecretStore({ [MANAGER_SECRET]: JSON.stringify(MANAGER) });
  const dependencies: ClientDependencies = {
    env: CONNECTOR_ENV,
    connectSecretManager: vault.connectSecretManager,
    knex: withoutTls,
  };
  const logger = createLogger();

  const validate = (
    overrides: ClientDependencies = {},
    database = target.database
  ) =>
    validationRouter(t, { ...dependencies, ...overrides })
      .createCaller({ logger })
      .get({ target: { ...target, database } });

  /** The roles the `role` access lists, signed in as the manager. */
  const listRoles = async () => {
    const client = await newClient(target, "rds", dependencies);
    try {
      return await listGrantableRoles(client, logger);
    } finally {
      await client.destroy();
    }
  };

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

  it("lists exactly the grantable roles for the role access", async () => {
    await expect(listRoles()).resolves.toEqual(
      GRANTABLE.map((role) => ({ key: role, value: role }))
    );
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
        [MANAGER_SECRET]: JSON.stringify({
          ...MANAGER,
          password: "not-the-password",
        }),
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

    it("fails as unavailable, with the shipped client, at a certificate AWS did not sign", async () => {
      const data = await dataOf(validate({ knex }));

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
    const vault = fakeSecretStore({
      [MANAGER_SECRET]: JSON.stringify(MANAGER),
    });

    const data = await dataOf(
      validationRouter(t, {
        env: CONNECTOR_ENV,
        connectSecretManager: vault.connectSecretManager,
        knex: withoutTls,
      })
        .createCaller({ logger: createLogger() })
        .get({
          target: {
            host: HOST,
            port: 1,
            database: "postgres",
            managerSecret: MANAGER_SECRET,
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
