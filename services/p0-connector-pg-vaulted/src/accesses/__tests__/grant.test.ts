import { UnauthorizedError } from "@p0security/connector-secret-manager-client";
import { inspect } from "node:util";
import { beforeEach, describe, expect, it } from "vitest";

import {
  type FakeRole,
  type Journal,
  MANAGER_SECRET_ARN,
  capturingLogger,
  dataOf,
  env,
  errorOf,
  fakeDatabase,
  fakeRandomBytes,
  fakeSecretStore,
  pgError,
  sdkError,
} from "../../__tests__/fakes.ts";
import {
  FIRST_PASSWORD,
  LOGIN,
  SECOND_PASSWORD,
  context,
} from "../../__tests__/fixtures.ts";
import { t } from "../../router.ts";
import { newRolePrimitives, router } from "../role/handler.ts";

const SECRET = context.secretName;
const DEADLINE = "2026-12-01T00:00:00Z";
const COMMENT = "request r123, requestor x@example.com";
const OTHER_LOGIN = `p0v_${"f".repeat(32)}`;

let journal: Journal = [];
let db = fakeDatabase();
let vault = fakeSecretStore();
let log = capturingLogger();
let randomBytes = fakeRandomBytes();

beforeEach(() => {
  journal = [];
  db = fakeDatabase({}, journal);
  vault = fakeSecretStore(undefined, journal);
  log = capturingLogger();
  randomBytes = fakeRandomBytes();
});

const dependencies = () => ({
  env,
  connectSecretManager: vault.connectSecretManager,
  secretsManagerSdk: vault.secretsManagerSdk,
  connect: db.connect,
  randomBytes,
});

const role = () =>
  router(t, dependencies()).createCaller({ logger: log.logger });

/** `createUser` itself. The perimeter calls it only after `getUser` found no
 * grant, so it meets an activated login only when another call got there
 * first. */
const create = () =>
  newRolePrimitives({ logger: log.logger }, dependencies()).createUser(
    context,
    LOGIN
  );

const provision = (requestContext = context) =>
  role().provisionUser({ userBody: LOGIN, context: requestContext });

const identify = () => role().identifyUser({ userBody: LOGIN, context });

const grant = (...rolenames: string[]) =>
  role().setPoliciesForUser({
    userId: LOGIN,
    userBody: LOGIN,
    policies: rolenames.map((rolename) => ({ type: "role", rolename })),
    context,
  });

/** A grant login as an earlier grant left it, in each state it can be in. */
const EARLIER = {
  password: "an earlier verifier",
  validUntil: "2026-11-01T00:00:00Z",
  comment: "an earlier comment",
};
const ROLES: Record<"active" | "prepared" | "retired", FakeRole> = {
  prepared: { canLogin: false, connectionLimit: -1, ...EARLIER },
  active: { canLogin: true, connectionLimit: -1, ...EARLIER },
  retired: { canLogin: false, connectionLimit: 0, ...EARLIER },
};

type State = keyof typeof ROLES | "absent";
type Secret = "absent" | "empty" | "filled";

/** Puts the grant login in `state`, and its grant secret in `secret`. */
const given = (state: State, secret: Secret) => {
  if (state !== "absent") db.roles.set(LOGIN, { ...ROLES[state] });
  if (secret === "empty") vault.holding(SECRET);
  if (secret === "filled") vault.holding(SECRET, "an earlier password");
};

/** What the grant path may change: the login and its memberships in
 * PostgreSQL, and its grant secret's values. */
const everything = () => ({
  roles: structuredClone([...db.roles]),
  memberships: structuredClone(db.memberships),
  secret: vault.secrets.get(SECRET)?.values.map(String),
});

const PREPARED_BY_THE_FIRST_CALL: FakeRole = {
  canLogin: false,
  connectionLimit: -1,
  password: FIRST_PASSWORD.verifier,
  validUntil: DEADLINE,
  comment: COMMENT,
};

describe("identifyUser", () => {
  it.each([
    ["absent", "absent", null],
    ["absent", "empty", null],
    ["absent", "filled", null],
    ["prepared", "absent", null],
    ["prepared", "empty", null],
    ["prepared", "filled", LOGIN],
    ["active", "absent", LOGIN],
    ["active", "empty", LOGIN],
    ["active", "filled", LOGIN],
    ["retired", "absent", LOGIN],
    ["retired", "empty", LOGIN],
    ["retired", "filled", LOGIN],
  ] as const)(
    "with the login %s and its grant secret %s, finds %j and changes nothing",
    async (state, secret, found) => {
      given(state, secret);
      const before = everything();

      await expect(identify()).resolves.toBe(found);

      expect(everything()).toEqual(before);
    }
  );

  it("reads the login's state as the manager, then describes the grant secret of a prepared login", async () => {
    given("prepared", "filled");

    await identify();

    expect(journal).toEqual([
      `getSecretValue ${MANAGER_SECRET_ARN}`,
      ["login", LOGIN],
      "close",
      `describeSecret ${SECRET}`,
    ]);
  });

  it.each(["active", "retired"] as const)(
    "finds a login that is %s without looking at its grant secret, so that a revoke never skips it",
    async (state) => {
      given(state, "absent");
      vault.state.failDescribe = sdkError("AccessDeniedException");

      await expect(identify()).resolves.toBe(LOGIN);

      expect(journal).toEqual([
        `getSecretValue ${MANAGER_SECRET_ARN}`,
        ["login", LOGIN],
        "close",
      ]);
    }
  );

  it("counts a grant secret that AWS is still deleting as absent", async () => {
    given("prepared", "filled");
    vault.secrets.set(SECRET, {
      values: [Buffer.from("an earlier password")],
      deletedDate: new Date(0),
    });

    await expect(identify()).resolves.toBe(null);
  });

  it("counts a grant secret whose versions have no staging label as having no value", async () => {
    given("prepared", "filled");
    vault.secrets.set(SECRET, {
      values: [Buffer.from("an earlier password")],
      unstaged: true,
    });

    await expect(identify()).resolves.toBe(null);
  });
});

describe("provisionUser", () => {
  it("prepares an absent login: the empty secret first, then the login, whose password is stored before the commit", async () => {
    await expect(provision()).resolves.toBe(LOGIN);

    expect(journal).toEqual([
      `getSecretValue ${MANAGER_SECRET_ARN}`,
      ["login", LOGIN],
      "close",
      `createSecret ${SECRET}`,
      `getSecretValue ${MANAGER_SECRET_ARN}`,
      "BEGIN",
      ["login", LOGIN],
      [
        "format",
        "CREATE ROLE %I NOLOGIN PASSWORD %L VALID UNTIL %L",
        LOGIN,
        FIRST_PASSWORD.verifier,
        "2026-12-01T00:00:00Z",
      ],
      `CREATE ROLE ${LOGIN} NOLOGIN PASSWORD '${FIRST_PASSWORD.verifier}' VALID UNTIL '2026-12-01T00:00:00Z'`,
      [
        "format",
        "COMMENT ON ROLE %I IS %L",
        LOGIN,
        "request r123, requestor x@example.com",
      ],
      `COMMENT ON ROLE ${LOGIN} IS 'request r123, requestor x@example.com'`,
      `createSecretVersion ${SECRET}`,
      "COMMIT",
      "close",
    ]);
    expect([...db.roles]).toEqual([[LOGIN, PREPARED_BY_THE_FIRST_CALL]]);
    expect(db.memberships).toEqual([]);
  });

  it("writes the password, and only the password, as the grant secret's value", async () => {
    await provision();

    expect(vault.secrets.get(SECRET)?.values.map(String)).toEqual([
      "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    ]);
  });

  it("gives a prepared login a new password, deadline and comment, and stores the password after the commit", async () => {
    given("prepared", "empty");

    await expect(provision()).resolves.toBe(LOGIN);

    expect(journal.slice(-3)).toEqual([
      "COMMIT",
      "close",
      `createSecretVersion ${SECRET}`,
    ]);
    expect(db.calls).toEqual([
      ["login", LOGIN],
      "close",
      "BEGIN",
      ["login", LOGIN],
      [
        "format",
        "ALTER ROLE %I PASSWORD %L VALID UNTIL %L",
        LOGIN,
        FIRST_PASSWORD.verifier,
        "2026-12-01T00:00:00Z",
      ],
      `ALTER ROLE ${LOGIN} PASSWORD '${FIRST_PASSWORD.verifier}' VALID UNTIL '2026-12-01T00:00:00Z'`,
      [
        "format",
        "COMMENT ON ROLE %I IS %L",
        LOGIN,
        "request r123, requestor x@example.com",
      ],
      `COMMENT ON ROLE ${LOGIN} IS 'request r123, requestor x@example.com'`,
      "COMMIT",
      "close",
    ]);
    expect(db.roles.get(LOGIN)).toEqual(PREPARED_BY_THE_FIRST_CALL);
  });

  it.each([
    ["a grant secret that was created and never written", "absent", "empty"],
    ["a grant secret left without its login", "absent", "filled"],
    ["a prepared login whose grant secret is gone", "prepared", "absent"],
    ["a prepared login whose grant secret has no value", "prepared", "empty"],
  ] as const)("finishes %s", async (_, state, secret) => {
    given(state, secret);

    await expect(provision()).resolves.toBe(LOGIN);

    expect(db.roles.get(LOGIN)).toEqual(PREPARED_BY_THE_FIRST_CALL);
    expect(vault.valueOf(SECRET)).toBe(FIRST_PASSWORD.password);
    await expect(identify()).resolves.toBe(LOGIN);
  });

  it.each(["prepared", "active", "retired"] as const)(
    "finds a %s login whose grant secret has a value, and changes nothing",
    async (state) => {
      given(state, "filled");
      const before = everything();

      await expect(provision()).resolves.toBe(LOGIN);

      expect(everything()).toEqual(before);
      expect(journal).toEqual([
        `getSecretValue ${MANAGER_SECRET_ARN}`,
        ["login", LOGIN],
        "close",
        ...(state === "prepared" ? [`describeSecret ${SECRET}`] : []),
      ]);
    }
  );

  it.each([
    [
      "active",
      "The grant login can already log in, so the connector will not set its password again.",
    ],
    [
      "retired",
      "The grant login is retired. A retired login is never given a password or activated again.",
    ],
  ] as const)(
    "createUser refuses a login that is %s, and leaves it as it was",
    async (state, message) => {
      given(state, "empty");
      const before = everything();

      await expect(dataOf(create())).resolves.toEqual({
        type: "dependency_violation",
        message,
        payload: { login: LOGIN, state },
      });

      expect(everything()).toEqual(before);
      expect(db.calls).toEqual([
        "BEGIN",
        ["login", LOGIN],
        "ROLLBACK",
        "close",
      ]);
    }
  );

  it("counts a login that cannot log in and has any connection limit as retired", async () => {
    db.roles.set(LOGIN, { ...ROLES.prepared, connectionLimit: 5 });

    const data = await dataOf(create());

    expect(data.payload).toEqual({ login: LOGIN, state: "retired" });
  });

  it("keeps the grant secret in the request's region, and reads the manager secret in its own", async () => {
    given("prepared", "empty");

    await provision({
      ...context,
      secrets: { manager: "aws", region: "eu-west-1" },
    });

    expect(vault.regions).toEqual(["eu-west-1", "eu-west-1", "eu-west-1"]);
    expect(vault.reads).toEqual([
      {
        config: { provider: "aws", region: "us-east-1" },
        ref: "arn:aws:secretsmanager:us-east-1:123456789012:secret:orders-manager-AbCdEf",
      },
      {
        config: { provider: "aws", region: "us-east-1" },
        ref: "arn:aws:secretsmanager:us-east-1:123456789012:secret:orders-manager-AbCdEf",
      },
    ]);
  });

  describe("when Secrets Manager refuses", () => {
    it.each([
      [
        "to describe the grant secret of a prepared login",
        () => {
          given("prepared", "empty");
          vault.state.failDescribe = sdkError("AccessDeniedException");
        },
        "Secrets Manager refused to let the connector look up the grant secret. Give the connector's role secretsmanager:DescribeSecret on the secrets under p0/postgres-ai/<vpc id>/.",
      ],
      [
        "to create the grant secret",
        () => {
          vault.state.failNextCreate = new UnauthorizedError("aws");
        },
        "Secrets Manager refused to let the connector create the grant secret. Give the connector's role secretsmanager:CreateSecret and secretsmanager:DescribeSecret on the secrets under p0/postgres-ai/<vpc id>/.",
      ],
    ])("%s, it leaves the database untouched", async (_, refuse, message) => {
      refuse();
      const before = everything();

      await expect(dataOf(provision())).resolves.toEqual({
        type: "insufficient_privileges",
        message,
        payload: {},
      });

      expect(everything()).toEqual(before);
      expect(db.calls).toEqual([["login", LOGIN], "close"]);
    });

    it("a new secret while it deletes the last one with the name, it fails as unavailable and leaves the database untouched", async () => {
      vault.secrets.set(SECRET, { values: [], deletedDate: new Date(0) });

      await expect(dataOf(provision())).resolves.toEqual({
        type: "upstream_unavailable",
        message:
          "Secrets Manager is still deleting an earlier grant secret with this name. Try again in a moment.",
        payload: {},
      });

      expect(db.calls).toEqual([["login", LOGIN], "close"]);
    });

    const WRITE_REFUSED = {
      type: "insufficient_privileges",
      message:
        "Secrets Manager refused to let the connector write the grant secret. Give the connector's role secretsmanager:PutSecretValue on the secrets under p0/postgres-ai/<vpc id>/.",
      payload: {},
    };

    it.each([
      ["no grant secret", "absent", undefined],
      ["an empty grant secret", "empty", []],
      [
        "a grant secret that holds an earlier value",
        "filled",
        ["an earlier password"],
      ],
    ] as const)(
      "to write the value of a new login with %s, it creates no login, and the next call finishes the grant",
      async (_, secret, values) => {
        given("absent", secret);
        vault.state.failNextWrite = () => new UnauthorizedError("aws");

        await expect(dataOf(provision())).resolves.toEqual(WRITE_REFUSED);

        expect([...db.roles]).toEqual([]);
        expect(db.calls.slice(-2)).toEqual(["ROLLBACK", "close"]);
        expect(vault.secrets.get(SECRET)?.values.map(String)).toEqual(
          values ?? []
        );
        await expect(identify()).resolves.toBe(null);

        await expect(provision()).resolves.toBe(LOGIN);

        expect(db.roles.get(LOGIN)).toEqual({
          ...PREPARED_BY_THE_FIRST_CALL,
          password: SECOND_PASSWORD.verifier,
        });
        expect(vault.valueOf(SECRET)).toBe(SECOND_PASSWORD.password);
      }
    );

    it("to write the value of a prepared login, the next call gives the login a new password and stores that", async () => {
      given("prepared", "empty");
      vault.state.failNextWrite = () => new UnauthorizedError("aws");

      await expect(dataOf(provision())).resolves.toEqual(WRITE_REFUSED);
      expect(db.roles.get(LOGIN)).toEqual(PREPARED_BY_THE_FIRST_CALL);
      expect(vault.secrets.get(SECRET)).toEqual({ values: [] });
      await expect(identify()).resolves.toBe(null);

      await expect(provision()).resolves.toBe(LOGIN);

      expect(db.roles.get(LOGIN)).toEqual({
        ...PREPARED_BY_THE_FIRST_CALL,
        password: SECOND_PASSWORD.verifier,
      });
      expect(vault.valueOf(SECRET)).toBe(SECOND_PASSWORD.password);
    });
  });

  describe("when PostgreSQL refuses", () => {
    it.each([
      ["CREATE ROLE", []],
      ["COMMENT ON ROLE", []],
      // The password is stored before the commit, and the next call
      // replaces it.
      ["COMMIT", [FIRST_PASSWORD.password]],
    ])(
      "%s after the grant secret was created, it leaves no login, and the next call finishes the grant",
      async (statement, stored) => {
        const stop = db.failOn(statement, pgError("42501"));

        const data = await dataOf(provision());

        expect(data.type).toBe("insufficient_privileges");
        expect(data.payload).toEqual({ sqlState: "42501" });
        expect([...db.roles]).toEqual([]);
        expect(vault.secrets.get(SECRET)?.values.map(String)).toEqual(stored);
        expect(db.calls.slice(-2)).toEqual(["ROLLBACK", "close"]);
        await expect(identify()).resolves.toBe(null);

        stop();
        await expect(provision()).resolves.toBe(LOGIN);

        expect(db.roles.get(LOGIN)).toEqual({
          ...PREPARED_BY_THE_FIRST_CALL,
          password: SECOND_PASSWORD.verifier,
        });
        expect(vault.valueOf(SECRET)).toBe(SECOND_PASSWORD.password);
      }
    );
  });
});

describe("setPoliciesForUser with policies", () => {
  it("grants the approved role and activates a prepared login, in one transaction", async () => {
    given("prepared", "filled");

    await expect(grant("analyst")).resolves.toBe(null);

    expect(db.calls).toEqual([
      "BEGIN",
      ["login", LOGIN],
      ["isGrantableRole", "analyst"],
      ["managerGrantedRoles", LOGIN],
      ["format", "GRANT %I TO %I", "analyst", LOGIN],
      `GRANT analyst TO ${LOGIN}`,
      [
        "format",
        "ALTER ROLE %I LOGIN VALID UNTIL %L",
        LOGIN,
        "2026-12-01T00:00:00Z",
      ],
      `ALTER ROLE ${LOGIN} LOGIN VALID UNTIL '2026-12-01T00:00:00Z'`,
      "COMMIT",
      "close",
    ]);
    expect(db.roles.get(LOGIN)).toEqual({
      canLogin: true,
      connectionLimit: -1,
      password: "an earlier verifier",
      validUntil: "2026-12-01T00:00:00Z",
      comment: "an earlier comment",
    });
    expect(db.memberships).toEqual([
      { role: "analyst", member: LOGIN, byManager: true },
    ]);
  });

  it("run again, grants nothing more and leaves the login as the first run did", async () => {
    given("prepared", "filled");
    await grant("analyst");
    const after = everything();
    db.calls.length = 0;

    await expect(grant("analyst")).resolves.toBe(null);

    expect(everything()).toEqual(after);
    expect(db.calls).toEqual([
      "BEGIN",
      ["login", LOGIN],
      ["isGrantableRole", "analyst"],
      ["managerGrantedRoles", LOGIN],
      [
        "format",
        "ALTER ROLE %I LOGIN VALID UNTIL %L",
        LOGIN,
        "2026-12-01T00:00:00Z",
      ],
      `ALTER ROLE ${LOGIN} LOGIN VALID UNTIL '2026-12-01T00:00:00Z'`,
      "COMMIT",
      "close",
    ]);
  });

  it.each([
    [
      "absent",
      "object_not_found",
      "The grant login does not exist in PostgreSQL.",
    ],
    [
      "retired",
      "dependency_violation",
      "The grant login is retired. A retired login is never given a password or activated again.",
    ],
  ] as const)(
    "refuses a login that is %s, and changes nothing",
    async (state, type, message) => {
      given(state, "filled");
      const before = everything();

      await expect(dataOf(grant("analyst"))).resolves.toEqual({
        type,
        message,
        payload: { login: LOGIN, state },
      });

      expect(everything()).toEqual(before);
      expect(db.calls).toEqual([
        "BEGIN",
        ["login", LOGIN],
        "ROLLBACK",
        "close",
      ]);
    }
  );

  it("refuses a role that is not grantable, names no other role, and leaves the login prepared", async () => {
    given("prepared", "filled");
    const before = everything();

    await expect(dataOf(grant("analyst", "postgres"))).resolves.toEqual({
      type: "validation_error",
      message: "The role postgres is not a grantable role of this target.",
      payload: { login: LOGIN, rolename: "postgres" },
    });

    expect(everything()).toEqual(before);
    expect(db.calls).toEqual([
      "BEGIN",
      ["login", LOGIN],
      ["isGrantableRole", "analyst"],
      ["isGrantableRole", "postgres"],
      "ROLLBACK",
      "close",
    ]);
  });

  it("makes the roles the manager granted equal the policies, and leaves every other membership", async () => {
    given("active", "filled");
    db.roles.set(OTHER_LOGIN, { ...ROLES.active });
    db.memberships.push(
      { role: "reporting", member: LOGIN, byManager: true },
      { role: "dba_team", member: LOGIN, byManager: false },
      { role: "reporting", member: OTHER_LOGIN, byManager: true }
    );

    await grant("analyst");

    expect(db.calls.slice(3, -2)).toEqual([
      ["managerGrantedRoles", LOGIN],
      ["format", "GRANT %I TO %I", "analyst", LOGIN],
      `GRANT analyst TO ${LOGIN}`,
      ["format", "REVOKE %I FROM %I", "reporting", LOGIN],
      `REVOKE reporting FROM ${LOGIN}`,
      [
        "format",
        "ALTER ROLE %I LOGIN VALID UNTIL %L",
        LOGIN,
        "2026-12-01T00:00:00Z",
      ],
      `ALTER ROLE ${LOGIN} LOGIN VALID UNTIL '2026-12-01T00:00:00Z'`,
    ]);
    expect(db.memberships).toEqual([
      { role: "dba_team", member: LOGIN, byManager: false },
      { role: "reporting", member: OTHER_LOGIN, byManager: true },
      { role: "analyst", member: LOGIN, byManager: true },
    ]);
  });

  it("grants each role of several policies once", async () => {
    given("prepared", "filled");

    await grant("reporting", "analyst", "reporting");

    expect(db.memberships).toEqual([
      { role: "reporting", member: LOGIN, byManager: true },
      { role: "analyst", member: LOGIN, byManager: true },
    ]);
  });

  it("has PostgreSQL quote a role name that needs it", async () => {
    db = fakeDatabase({ grantableRoles: ["Reporting.read-only"] }, journal);
    given("prepared", "filled");

    await grant("Reporting.read-only");

    expect(db.calls).toContain(`GRANT "Reporting.read-only" TO ${LOGIN}`);
    expect(db.memberships).toEqual([
      { role: "Reporting.read-only", member: LOGIN, byManager: true },
    ]);
  });

  it.each([`ALTER ROLE ${LOGIN} LOGIN`, "COMMIT"])(
    "takes back the grant when PostgreSQL refuses %s",
    async (statement) => {
      given("prepared", "filled");
      const before = everything();
      db.failOn(statement, pgError("42501"));

      const data = await dataOf(grant("analyst"));

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({ sqlState: "42501" });
      expect(everything()).toEqual(before);
      expect(db.calls).toContain(`GRANT analyst TO ${LOGIN}`);
      expect(db.calls.slice(-2)).toEqual(["ROLLBACK", "close"]);
    }
  );

  it("reaches Secrets Manager only for the manager secret", async () => {
    given("prepared", "filled");
    const before = everything();

    await grant("analyst");

    expect(journal.filter((call) => typeof call === "string")).toEqual([
      `getSecretValue ${MANAGER_SECRET_ARN}`,
      "BEGIN",
      `GRANT analyst TO ${LOGIN}`,
      `ALTER ROLE ${LOGIN} LOGIN VALID UNTIL '2026-12-01T00:00:00Z'`,
      "COMMIT",
      "close",
    ]);
    expect(everything().secret).toEqual(before.secret);
  });
});

describe("a grant, from provisionUser to setPoliciesForUser", () => {
  it("ends with a login that can log in, holds the approved role, and has the stored password", async () => {
    await provision();
    await grant("analyst");

    expect(everything()).toEqual({
      roles: [[LOGIN, { ...PREPARED_BY_THE_FIRST_CALL, canLogin: true }]],
      memberships: [{ role: "analyst", member: LOGIN, byManager: true }],
      secret: [FIRST_PASSWORD.password],
    });
  });

  it("run again, changes nothing", async () => {
    await provision();
    await grant("analyst");
    const after = everything();

    await expect(provision()).resolves.toBe(LOGIN);
    await expect(grant("analyst")).resolves.toBe(null);

    expect(everything()).toEqual(after);
  });

  it("never reads the grant secret's value", async () => {
    await provision();
    await grant("analyst");
    await identify();

    expect(vault.reads.map(({ ref }) => ref)).toEqual([
      MANAGER_SECRET_ARN,
      MANAGER_SECRET_ARN,
      MANAGER_SECRET_ARN,
      MANAGER_SECRET_ARN,
    ]);
  });
});

describe("the grant login's password", () => {
  const SECRETS = [
    FIRST_PASSWORD.password,
    FIRST_PASSWORD.verifier,
    "SCRAM-SHA-256",
    "NOLOGIN PASSWORD",
  ];

  /** Everything a failed call shows: the error with its causes, and the
   * log. */
  const shownBy = async (call: Promise<unknown>) => {
    const error = await errorOf(call);
    return `${inspect(error, { depth: 10 })}\n${log.lines.join("")}`;
  };

  const expectNoSecretIn = (shown: string) => {
    for (const secret of SECRETS) expect(shown).not.toContain(secret);
  };

  it("is in no log line of a grant, and neither is its verifier or a statement", async () => {
    await provision();
    await grant("analyst");

    const logged = log.lines.join("");
    expect(logged).toContain(
      "prepared the grant login and stored its password"
    );
    expect(logged).toContain('"from":"absent","to":"prepared"');
    expect(logged).toContain(
      "granted the approved roles and activated the grant login"
    );
    expect(logged).toContain(
      '"from":"prepared","to":"active","roles":["analyst"],"granted":["analyst"],"revoked":[]'
    );
    expect(logged).toContain(`"login":"${LOGIN}"`);
    expectNoSecretIn(logged);
  });

  it.each(["format", "CREATE ROLE", "COMMENT ON ROLE"])(
    "is in no error and no log line when PostgreSQL's error quotes the statement and bindings of %s",
    async (statement) => {
      db.failOn(statement, (sql, bindings) =>
        pgError("42501", `${sql} ${bindings.join(" ")}`)
      );

      const shown = await shownBy(provision());

      expect(shown).toContain("connector request errored");
      expect(shown).toContain("42501");
      expectNoSecretIn(shown);
    }
  );

  it("is in no error and no log line when PostgreSQL's error quotes the statement that resets it", async () => {
    given("prepared", "empty");
    db.failOn("ALTER ROLE", (sql) => pgError("42501", sql));

    const shown = await shownBy(provision());

    expect(shown).toContain("42501");
    expectNoSecretIn(shown);
  });

  it("is in no error and no log line when the secret manager's error quotes the value it would not write", async () => {
    vault.state.failNextWrite = (value) =>
      new Error(`PutSecretValue ${value.toString()}`, {
        cause: new Error(value.toString()),
      });

    const shown = await shownBy(provision());

    expect(shown).toContain("The connector could not write the grant secret.");
    expectNoSecretIn(shown);
  });
});
