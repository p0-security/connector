import { createLogger } from "@p0security/connector-core";
import { inspect } from "node:util";
import pg from "pg";
import { beforeEach, describe, expect, it } from "vitest";
import { z } from "zod";

import { router as roleRouter } from "../accesses/role/handler.ts";
import type { RequestContext } from "../context.ts";
import type { Dependencies } from "../dependencies.ts";
import { router as validationRouter } from "../install/handler.ts";
import { connect, connectWith } from "../postgres/client.ts";
import { t } from "../router.ts";
import {
  capturingLogger,
  connectorErrorOf,
  dataOf,
  errorOf,
  fakeSecretStore,
} from "./fakes.ts";

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

/** The grant login the grant tests prepare, which no fixture creates. */
const GRANTED_LOGIN = `p0v_${"b".repeat(32)}`;
const GRANT_SECRET = `p0/postgres-ai/vpc-0a1b2c3d4e5f67890/it-target/${GRANTED_LOGIN}`;
// With an offset, and far enough ahead that the login can sign in.
const DEADLINE = "2099-01-01T00:00:00+02:00";
const COMMENT = "request it-1, requestor x@example.com";

/** What the catalog holds of the grant login, as the superuser reads it. */
const grantLoginRows = z.array(
  z.object({
    rolcanlogin: z.boolean(),
    rolconnlimit: z.number(),
    rolpassword: z.string(),
    rolvaliduntil: z.date().nullable(),
    comment: z.string().nullable(),
    memberships: z.array(z.string()).nullable(),
  })
);

/** The SQLSTATE of a sign-in that PostgreSQL refused. */
const refusal = z.object({ code: z.string() });

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
  const target = { host: HOST, port, database: "postgres" };

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

  let vault = fakeSecretStore({ [ARN]: JSON.stringify(MANAGER) });
  const dependencies = (): Dependencies => ({
    env: {
      MANAGER_SECRET_ARNS: JSON.stringify({
        [HOST]: { arn: ARN, targetId: "it-target" },
      }),
    },
    connectSecretManager: vault.connectSecretManager,
    secretsManagerSdk: vault.secretsManagerSdk,
    connect: connectWith(false),
  });
  const logger = createLogger();

  const validate = (overrides: Dependencies = {}, database = target.database) =>
    validationRouter(t, { ...dependencies(), ...overrides })
      .createCaller({ logger })
      .get({ target: { ...target, database } });

  const list = (type: "database" | "role") =>
    roleRouter(t, dependencies())
      .createCaller({ logger })
      .list({ query: { type, context: target } });

  const GRANTABLE = ["analyst", "reporting"];

  beforeEach(async () => {
    vault = fakeSecretStore({ [ARN]: JSON.stringify(MANAGER) });
    await asSuperuser(
      // First, so that the memberships the manager granted it go with it.
      `DROP ROLE IF EXISTS "${GRANTED_LOGIN}"`,
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

  describe("a grant", () => {
    const context = (overrides: Partial<RequestContext> = {}) => ({
      requestId: "it-1",
      target,
      secrets: { manager: "aws" as const, region: "us-east-1" },
      secretName: GRANT_SECRET,
      deadline: DEADLINE,
      comment: COMMENT,
      objectOwner: "analyst",
      ...overrides,
    });

    const role = () => roleRouter(t, dependencies()).createCaller({ logger });

    const provision = (overrides?: Partial<RequestContext>) =>
      role().provisionUser({
        userBody: GRANTED_LOGIN,
        context: context(overrides),
      });

    const identify = () =>
      role().identifyUser({ userBody: GRANTED_LOGIN, context: context() });

    const approve = (
      rolenames: string[],
      overrides?: Partial<RequestContext>
    ) =>
      role().setPoliciesForUser({
        userId: GRANTED_LOGIN,
        userBody: GRANTED_LOGIN,
        policies: rolenames.map((rolename) => ({ type: "role", rolename })),
        context: context(overrides),
      });

    /** The grant login's catalog row, with each of its memberships and who
     * granted it. */
    const grantLogin = async () => {
      const [login] = grantLoginRows.parse(
        await asSuperuser(
          `SELECT a.rolcanlogin, a.rolconnlimit, a.rolpassword, a.rolvaliduntil,
            shobj_description(a.oid, 'pg_authid') AS comment,
            (SELECT array_agg(m.roleid::regrole::text || ' by ' || m.grantor::regrole::text
                ORDER BY m.roleid::regrole::text, m.grantor::regrole::text)
              FROM pg_auth_members m WHERE m.member = a.oid) AS memberships
          FROM pg_authid a WHERE a.rolname = '${GRANTED_LOGIN}'`
        )
      );
      if (!login) throw new Error("the grant login does not exist");
      return login;
    };

    /** The password the connector stored, which it cannot read itself. */
    const storedPassword = () => vault.valueOf(GRANT_SECRET) ?? "";

    /** Signs in as the grant login over TCP. Returns the user PostgreSQL
     * says it is, or the SQLSTATE PostgreSQL refused the sign-in with. */
    const signIn = async (password: string) => {
      const client = new pg.Client({
        host: HOST,
        port,
        database: "postgres",
        user: GRANTED_LOGIN,
        password,
      });
      try {
        await client.connect();
        const { rows } = await client.query("SELECT current_user AS name");
        return z.tuple([z.object({ name: z.string() })]).parse(rows)[0].name;
      } catch (error) {
        return refusal.parse(error).code;
      } finally {
        await client.end();
      }
    };

    it("ends with a login that signs in with the stored password, holds exactly the approved role, and has the deadline and the comment", async () => {
      await expect(provision()).resolves.toBe(GRANTED_LOGIN);
      await expect(approve(["analyst"])).resolves.toBe(null);

      expect(storedPassword()).toMatch(/^[A-Za-z0-9_-]{43}$/);
      await expect(signIn(storedPassword())).resolves.toBe(GRANTED_LOGIN);
      expect(await grantLogin()).toEqual({
        rolcanlogin: true,
        rolconnlimit: -1,
        rolpassword: expect.stringMatching(/^SCRAM-SHA-256\$4096:/),
        rolvaliduntil: new Date("2098-12-31T22:00:00Z"),
        comment: "request it-1, requestor x@example.com",
        memberships: ["analyst by it_manager"],
      });
    });

    it("signs in by SCRAM-SHA-256, which refuses any other password", async () => {
      await provision();
      await approve(["analyst"]);

      await expect(signIn("not-the-password")).resolves.toBe("28P01");
      // The rule a sign-in from outside the container meets.
      expect(
        await asSuperuser(
          "SELECT auth_method FROM pg_hba_file_rules WHERE type = 'host' AND address = 'all'"
        )
      ).toEqual([{ auth_method: "scram-sha-256" }]);
    });

    it("cannot sign in while the login is prepared", async () => {
      await provision();

      await expect(signIn(storedPassword())).resolves.toBe("28000");
      expect(await grantLogin()).toMatchObject({
        rolcanlogin: false,
        rolconnlimit: -1,
        memberships: null,
      });
    });

    it("changes nothing when each step runs again", async () => {
      await provision();
      const prepared = await grantLogin();
      const password = storedPassword();

      await expect(provision()).resolves.toBe(GRANTED_LOGIN);

      expect(await grantLogin()).toEqual(prepared);
      expect(storedPassword()).toBe(password);

      await approve(["analyst"]);
      const active = await grantLogin();

      await expect(provision()).resolves.toBe(GRANTED_LOGIN);
      await expect(approve(["analyst"])).resolves.toBe(null);

      expect(await grantLogin()).toEqual(active);
      expect(active.rolpassword).toBe(prepared.rolpassword);
      expect(storedPassword()).toBe(password);
      await expect(signIn(password)).resolves.toBe(GRANTED_LOGIN);
    });

    it("creates no login when its password could not be stored, and the next call finishes the grant", async () => {
      vault.state.failNextWrite = () => new Error("the write was lost");
      const data = await dataOf(provision());

      expect(data.type).toBe("upstream_unavailable");
      await expect(grantLogin()).rejects.toThrow(
        "the grant login does not exist"
      );

      await expect(provision()).resolves.toBe(GRANTED_LOGIN);
      await approve(["analyst"]);

      expect(vault.secrets.get(GRANT_SECRET)?.values).toHaveLength(1);
      await expect(signIn(storedPassword())).resolves.toBe(GRANTED_LOGIN);
    });

    it("gives a prepared login a new password that works, when its first was never stored", async () => {
      await provision();
      const first = await grantLogin();
      // The prepared login's secret lost its value, and the next write fails.
      vault.holding(GRANT_SECRET);
      vault.state.failNextWrite = () => new Error("the write was lost");
      const data = await dataOf(provision());

      expect(data.type).toBe("upstream_unavailable");
      await expect(identify()).resolves.toBe(null);

      await expect(provision()).resolves.toBe(GRANTED_LOGIN);
      await approve(["analyst"]);

      expect((await grantLogin()).rolpassword).not.toBe(first.rolpassword);
      expect(vault.secrets.get(GRANT_SECRET)?.values).toHaveLength(1);
      await expect(signIn(storedPassword())).resolves.toBe(GRANTED_LOGIN);
    });

    it("refuses a retired login, and leaves it retired with its password as it was", async () => {
      await provision();
      await approve(["analyst"]);
      await asSuperuser(
        `ALTER ROLE "${GRANTED_LOGIN}" NOLOGIN CONNECTION LIMIT 0`
      );
      const retired = await grantLogin();

      await expect(dataOf(approve(["analyst"]))).resolves.toMatchObject({
        type: "dependency_violation",
        payload: { login: GRANTED_LOGIN, state: "retired" },
      });
      // Its secret lost its value. A revoke still finds the login, and a
      // grant finds it too, so nothing prepares it again.
      vault.holding(GRANT_SECRET);
      await expect(identify()).resolves.toBe(GRANTED_LOGIN);
      await expect(provision()).resolves.toBe(GRANTED_LOGIN);

      expect(retired.rolconnlimit).toBe(0);
      expect(await grantLogin()).toEqual(retired);
      expect(vault.valueOf(GRANT_SECRET)).toBe(undefined);
    });

    it("with a deadline in the past, makes a login that cannot sign in", async () => {
      const past = { deadline: "2020-01-01T00:00:00Z" };

      await provision(past);
      await approve(["analyst"], past);

      expect(await grantLogin()).toMatchObject({
        rolcanlogin: true,
        rolvaliduntil: new Date("2020-01-01T00:00:00Z"),
      });
      await expect(signIn(storedPassword())).resolves.toBe("28P01");
    });

    it("stores a comment with quotes, backslashes, dollar signs, question marks, percent signs and a newline as it is", async () => {
      const comment = `it's "quoted" \\ back\\\\slash $$ dollar $1 why? \\? 100% %I %L\nsecond line; DROP ROLE analyst; --`;

      await provision({ comment });

      expect((await grantLogin()).comment).toBe(comment);
      expect(await list("role")).toEqual(
        GRANTABLE.map((name) => ({ key: name, value: name }))
      );
    });

    it("refuses a role that is not grantable, and leaves the login prepared", async () => {
      await provision();
      const prepared = await grantLogin();

      await expect(dataOf(approve(["analyst", "unshared"]))).resolves.toEqual({
        type: "validation_error",
        message: "The role unshared is not a grantable role of this target.",
        payload: { login: GRANTED_LOGIN, rolename: "unshared" },
      });

      expect(await grantLogin()).toEqual(prepared);
    });

    it.each(["it_superuser", "pg_read_all_data"])(
      "refuses %s, which the manager holds ADMIN OPTION on, and changes nothing",
      async (rolename) => {
        await provision();
        const prepared = await grantLogin();
        const before = await rolesAndMemberships();

        await expect(dataOf(approve(["analyst", rolename]))).resolves.toEqual({
          type: "validation_error",
          message: `The role ${rolename} is not a grantable role of this target.`,
          payload: { login: GRANTED_LOGIN, rolename },
        });

        expect(await grantLogin()).toEqual(prepared);
        expect(await rolesAndMemberships()).toEqual(before);
      }
    );

    it("keeps the statement and the verifier out of the error and the log when PostgreSQL refuses to create the login", async () => {
      await asSuperuser(`ALTER ROLE ${MANAGER.username} NOCREATEROLE`);
      const log = capturingLogger();

      const error = await errorOf(
        roleRouter(t, dependencies())
          .createCaller({ logger: log.logger })
          .provisionUser({ userBody: GRANTED_LOGIN, context: context() })
      );

      expect(connectorErrorOf(error).data).toMatchObject({
        type: "insufficient_privileges",
        payload: { sqlState: "42501" },
      });
      const shown = `${inspect(error, { depth: 10 })}\n${log.lines.join("")}`;
      expect(shown).toContain("connector request errored");
      expect(shown).not.toContain("SCRAM-SHA-256");
      expect(shown).not.toContain("CREATE ROLE");
      expect(vault.secrets.get(GRANT_SECRET)).toEqual({ values: [] });
    });

    it("refuses a login that does not exist", async () => {
      await expect(dataOf(approve(["analyst"]))).resolves.toMatchObject({
        type: "object_not_found",
        payload: { login: GRANTED_LOGIN, state: "absent" },
      });
    });

    it("makes the roles the manager granted equal the policies, and leaves a membership another login granted", async () => {
      await provision();
      await approve(["analyst"]);
      await asSuperuser(`GRANT unshared TO "${GRANTED_LOGIN}"`);

      await approve(["reporting"]);

      expect((await grantLogin()).memberships).toEqual([
        "reporting by it_manager",
        "unshared by postgres",
      ]);
    });

    it("grants and takes back a role whose ADMIN OPTION the manager holds through another role", async () => {
      await asSuperuser(
        `REVOKE reporting FROM ${MANAGER.username}`,
        "GRANT reporting TO it_group WITH ADMIN OPTION",
        `GRANT it_group TO ${MANAGER.username}`
      );
      // From PostgreSQL 16 the grantor is the role whose ADMIN OPTION the
      // manager used.
      const grantor = version >= 16 ? "it_group" : "it_manager";
      await provision();

      await approve(["reporting"]);
      await approve(["reporting"]);

      expect((await grantLogin()).memberships).toEqual([
        `reporting by ${grantor}`,
      ]);

      await approve(["analyst"]);

      expect((await grantLogin()).memberships).toEqual([
        "analyst by it_manager",
      ]);
    });

    it("takes back a role the manager reaches another way since the grant, whose grantor is no longer the one PostgreSQL infers", async () => {
      await asSuperuser(
        `REVOKE reporting FROM ${MANAGER.username}`,
        "GRANT reporting TO it_group WITH ADMIN OPTION",
        `GRANT it_group TO ${MANAGER.username}`
      );
      const grantor = version >= 16 ? "it_group" : "it_manager";
      await provision();
      await approve(["reporting"]);
      expect((await grantLogin()).memberships).toEqual([
        `reporting by ${grantor}`,
      ]);
      // A plain REVOKE by the manager now only prints a warning on
      // PostgreSQL 16 and later, and leaves the membership of it_group.
      await asSuperuser(
        `GRANT reporting TO ${MANAGER.username} WITH ADMIN OPTION`
      );

      await approve(["analyst"]);

      expect((await grantLogin()).memberships).toEqual([
        "analyst by it_manager",
      ]);
    });
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
        .get({ target: { host: HOST, port: 1, database: "postgres" } })
    );

    expect(data.type).toBe("upstream_unavailable");
    expect(data.payload).toEqual({
      code: "ECONNREFUSED",
      step: "sign_in",
      host: HOST,
    });
  });
});
