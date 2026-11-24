import { buildResourceRootSecurityPerimeter } from "@p0security/connector-core";
import { inspect } from "node:util";
import { beforeEach, describe, expect, it } from "vitest";

import {
  MANAGER,
  capturingLogger,
  dataOf,
  errorOf,
  fakeDatabase,
  fakeRandomBytes,
  fakeSecretStore,
  networkError,
  pgError,
} from "../../__tests__/fakes.ts";
import { LOGIN, context, target } from "../../__tests__/fixtures.ts";
import type { Dependencies } from "../../dependencies.ts";
import { t } from "../../router.ts";
import { spec } from "../role/definition.ts";
import { newRolePrimitives, router } from "../role/handler.ts";

let db = fakeDatabase();
let vault = fakeSecretStore();
let log = capturingLogger();

beforeEach(() => {
  db = fakeDatabase();
  vault = fakeSecretStore();
  log = capturingLogger();
});

const dependencies = (overrides: Dependencies = {}): Dependencies => ({
  connectSecretManager: vault.connectSecretManager,
  secretsManagerSdk: vault.secretsManagerSdk,
  connect: db.connect,
  randomBytes: fakeRandomBytes(),
  ...overrides,
});

const role = (overrides?: Dependencies) =>
  router(t, dependencies(overrides)).createCaller({ logger: log.logger });

const approved = [{ type: "role" as const, rolename: "analyst" }];

const OTHER_LOGIN = `p0v_${"f".repeat(32)}`;

describe("request parsing", () => {
  it.each(["postgres", "p0v_", `${LOGIN}0`, `${LOGIN}"; DROP ROLE x; --`])(
    "refuses the login %j",
    async (login) => {
      await expect(
        role().provisionUser({ userBody: login, context })
      ).rejects.toThrow("Invalid string");
      await expect(
        role().deleteUser({ userId: login, userBody: LOGIN, context })
      ).rejects.toThrow("Invalid string");
    }
  );

  it.each([
    "",
    "has space",
    'analyst"; DROP ROLE x; --',
    "rôle",
    "a".repeat(64),
  ])("refuses the role name %j", async (rolename) => {
    await expect(
      role().setPoliciesForUser({
        userId: LOGIN,
        userBody: LOGIN,
        policies: [{ type: "role", rolename }],
        context,
      })
    ).rejects.toThrow("rolename");
  });

  it.each(["analyst", "Reporting.read-only", "x@example.com", "a".repeat(63)])(
    "accepts the role name %j",
    (rolename) => {
      const policy = { type: "role", rolename };

      expect(spec.policy(policy)).toEqual(policy);
    }
  );

  it("refuses a policy that is not a role", async () => {
    await expect(
      role().setPoliciesForUser({
        userId: LOGIN,
        userBody: LOGIN,
        // @ts-expect-error -- the only policy type is "role"
        policies: [{ type: "sql", rolename: "analyst" }],
        context,
      })
    ).rejects.toThrow("policies");
  });

  it("refuses a context with no target id", async () => {
    const { targetId: _, ...withoutTargetId } = context;

    await expect(
      // @ts-expect-error -- the context has a target id
      role().provisionUser({ userBody: LOGIN, context: withoutTargetId })
    ).rejects.toThrow("targetId");
  });

  it("refuses a lister type other than role and database", async () => {
    await expect(
      // @ts-expect-error -- the only lister types are "role" and "database"
      role().list({ query: { type: "table", context: target } })
    ).rejects.toThrow("type");
  });
});

// The parsers already refuse a login outside the namespace, so the
// perimeter's own check is reached only without them.
describe("user namespace", () => {
  const perimeter = () =>
    buildResourceRootSecurityPerimeter(
      newRolePrimitives({ logger: log.logger }, dependencies())
    );

  it("refuses to provision or identify a login outside the namespace", async () => {
    await expect(
      perimeter().provisionUser({ userBody: "postgres", context })
    ).rejects.toThrow('Username "postgres" is not namespaced');
    await expect(
      perimeter().identifyUser({ userBody: "postgres", context })
    ).rejects.toThrow('Username "postgres" is not namespaced');
  });

  it.each(["deleteUser", "setPoliciesForUser"] as const)(
    "%s refuses a login outside the namespace, by id and by body",
    async (method) => {
      await expect(
        perimeter()[method]({
          userId: "postgres",
          userBody: LOGIN,
          policies: approved,
          context,
        })
      ).rejects.toThrow("Resource postgres is not namespaced");
      await expect(
        perimeter()[method]({
          userId: LOGIN,
          userBody: "postgres",
          policies: approved,
          context,
        })
      ).rejects.toThrow('Username "postgres" is not namespaced');
    }
  );

  it("refuses a login whose grant secret is another login's", async () => {
    await expect(
      perimeter().provisionUser({ userBody: OTHER_LOGIN, context })
    ).rejects.toThrow(`Username "${OTHER_LOGIN}" is not namespaced`);
    await expect(
      perimeter().deleteUser({
        userId: OTHER_LOGIN,
        userBody: OTHER_LOGIN,
        context,
      })
    ).rejects.toThrow(`Resource ${OTHER_LOGIN} is not namespaced`);
  });

  it("refuses every login before it reaches Secrets Manager or PostgreSQL", async () => {
    await expect(
      perimeter().provisionUser({ userBody: OTHER_LOGIN, context })
    ).rejects.toThrow("is not namespaced");

    expect(vault.regions).toEqual([]);
    expect(db.signIns).toEqual([]);
  });

  it("lets a grant login through to the primitives", async () => {
    await expect(
      perimeter().provisionUser({ userBody: LOGIN, context })
    ).resolves.toBe(LOGIN);
    expect([...db.roles.keys()]).toEqual([LOGIN]);
  });
});

describe("list", () => {
  const list = (type: "database" | "role", overrides?: Dependencies) =>
    role(overrides).list({ query: { type, context: target } });

  it("lists the grantable roles as the manager, then closes the connection", async () => {
    await expect(list("role")).resolves.toEqual([
      { key: "analyst", value: "analyst" },
      { key: "reporting", value: "reporting" },
    ]);
    expect(db.signIns).toEqual([
      {
        host: "orders.cluster-abc123.us-east-1.rds.amazonaws.com",
        port: 5432,
        database: "postgres",
        username: "p0_manager",
        password: "correct-horse-battery-staple",
      },
    ]);
    expect(db.calls).toEqual(["grantableRoles", "close"]);
  });

  it("leaves out a role whose name no policy can hold", async () => {
    db = fakeDatabase({ grantableRoles: ["Sales Team", "analyst", "rôle"] });

    await expect(list("role")).resolves.toEqual([
      { key: "analyst", value: "analyst" },
    ]);
  });

  it("lists the databases", async () => {
    await expect(list("database")).resolves.toEqual([
      { key: "orders", value: "orders" },
      { key: "postgres", value: "postgres" },
    ]);
    expect(db.calls).toEqual(["connectableDatabases", "close"]);
  });

  it("lists only the databases the manager can connect to", async () => {
    db = fakeDatabase({
      databases: ["billing", "orders", "postgres"],
      closedDatabases: ["billing"],
    });

    await expect(list("database")).resolves.toEqual([
      { key: "orders", value: "orders" },
      { key: "postgres", value: "postgres" },
    ]);
  });

  it("reads the manager secret the target names, in the region its ARN names", async () => {
    const managerSecretArn =
      "arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:billing-manager-AbCdEf";
    vault = fakeSecretStore({ [managerSecretArn]: JSON.stringify(MANAGER) });

    await expect(
      role().list({
        query: { type: "role", context: { ...target, managerSecretArn } },
      })
    ).resolves.toEqual([
      { key: "analyst", value: "analyst" },
      { key: "reporting", value: "reporting" },
    ]);

    expect(vault.reads).toEqual([
      {
        config: { provider: "aws", region: "cn-north-1" },
        ref: managerSecretArn,
      },
    ]);
  });

  it("fails as not found when the target's manager secret does not exist", async () => {
    vault = fakeSecretStore({});

    const data = await dataOf(list("role"));

    expect(data.type).toBe("object_not_found");
    expect(data.payload).toEqual({});
    expect(db.signIns).toEqual([]);
  });

  it.each([
    ["28P01", "insufficient_privileges"],
    ["28000", "insufficient_privileges"],
    ["42501", "insufficient_privileges"],
    ["42704", "object_not_found"],
    ["3D000", "object_not_found"],
    ["42710", "already_exists"],
    ["2BP01", "dependency_violation"],
    ["08006", "upstream_unavailable"],
    ["53300", "upstream_unavailable"],
    ["57014", "upstream_unavailable"],
    ["55P03", "upstream_unavailable"],
    ["57P03", "upstream_unavailable"],
    ["23505", "unknown"],
    ["XX000", "unknown"],
  ])(
    "maps PostgreSQL's SQLSTATE %s to %s, and keeps the statement out of the error",
    async (sqlState, type) => {
      db.failOn("grantableRoles", pgError(sqlState, "select rolname"));

      const data = await dataOf(list("role"));

      expect(data.type).toBe(type);
      expect(data.payload).toEqual({ sqlState });
      expect(data.message).not.toContain("select rolname");
      expect(db.calls).toEqual(["grantableRoles", "close"]);
    }
  );

  it.each([
    ["a refused connection", networkError("ECONNREFUSED"), "ECONNREFUSED"],
    // Five capitals, as a SQLSTATE can be, but no server sent it.
    ["a broken pipe", networkError("EPIPE"), "EPIPE"],
    [
      "a certificate the connector does not trust",
      networkError("SELF_SIGNED_CERT_IN_CHAIN"),
      "SELF_SIGNED_CERT_IN_CHAIN",
    ],
  ])("maps %s to unavailable, with its code", async (_, error, code) => {
    db.failOn("connectableDatabases", error);

    const data = await dataOf(list("database"));

    expect(data.type).toBe("upstream_unavailable");
    expect(data.payload).toEqual({ code });
  });

  it("maps a timeout that has no code to unavailable", async () => {
    db.failOn("connectableDatabases", new Error("timeout expired"));

    const data = await dataOf(list("database"));

    expect(data.type).toBe("upstream_unavailable");
    expect(data.payload).toEqual({});
  });

  describe("the manager's password", () => {
    /** Everything a failed call shows: the error with its causes, and the
     * log. */
    const shownBy = async (call: Promise<unknown>) => {
      const error = await errorOf(call);
      return `${inspect(error, { depth: 10 })}\n${log.lines.join("")}`;
    };

    it("is in no error and no log line when PostgreSQL's error quotes it", async () => {
      db.failOn(
        "grantableRoles",
        pgError("42501", `ALTER ROLE x PASSWORD '${MANAGER.password}'`)
      );

      const shown = await shownBy(list("role"));

      expect(shown).toContain("connector request errored");
      expect(shown).toContain("42501");
      expect(shown).not.toContain(MANAGER.password);
    });

    it("is in no error and no log line when the network error quotes it", async () => {
      db.failOn(
        "connectableDatabases",
        Object.assign(new Error(`connect failed for ${MANAGER.password}`), {
          code: "ECONNRESET",
        })
      );

      const shown = await shownBy(list("database"));

      expect(shown).toContain("ECONNRESET");
      expect(shown).not.toContain(MANAGER.password);
    });

    it("is in no error and no log line when the secret manager's error quotes the secret", async () => {
      vault.state.fail = new Error(`response ${JSON.stringify(MANAGER)}`, {
        cause: new Error(JSON.stringify(MANAGER)),
      });

      const shown = await shownBy(list("role"));

      expect(shown).toContain(
        "The connector could not read the manager secret."
      );
      expect(shown).not.toContain(MANAGER.password);
    });

    it("is in no log line of a list", async () => {
      await list("role");

      const logged = log.lines.join("");
      expect(logged).toContain("listed from the PostgreSQL target");
      expect(logged).not.toContain(MANAGER.password);
    });
  });
});
