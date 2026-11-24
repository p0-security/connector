import { ConnectorError } from "@p0security/connector-core";
import { UnauthorizedError } from "@p0security/connector-secret-manager-client";
import { inspect } from "node:util";
import { beforeEach, describe, expect, it } from "vitest";
import { z } from "zod";

import {
  type FakeObject,
  type FakeRole,
  type Journal,
  MANAGER_SECRET_ARN,
  capturingLogger,
  connectorErrorOf,
  dataOf,
  errorOf,
  fakeDatabase,
  fakeRandomBytes,
  fakeSecretStore,
  fakeWait,
  pgError,
} from "../../__tests__/fakes.ts";
import { LOGIN, context } from "../../__tests__/fixtures.ts";
import type { RequestContext } from "../../context.ts";
import { t } from "../../router.ts";
import { router } from "../role/handler.ts";

const SECRET = context.secretName;

/** The parts of a log line that a test reads. */
const logLine = z.object({ msg: z.string(), database: z.string().optional() });
const OTHER_LOGIN = `p0v_${"f".repeat(32)}`;

let journal: Journal = [];
let db = fakeDatabase();
let vault = fakeSecretStore();
let log = capturingLogger();
let wait = fakeWait(journal);

beforeEach(() => {
  journal = [];
  db = fakeDatabase({}, journal);
  vault = fakeSecretStore(undefined, journal);
  log = capturingLogger();
  wait = fakeWait(journal);
});

const role = () =>
  router(t, {
    connectSecretManager: vault.connectSecretManager,
    secretsManagerSdk: vault.secretsManagerSdk,
    connect: db.connect,
    randomBytes: fakeRandomBytes(),
    wait,
  }).createCaller({ logger: log.logger });

const user = { userId: LOGIN, userBody: LOGIN, context };

const provision = () => role().provisionUser({ userBody: LOGIN, context });

const approve = (rolename: string) =>
  role().setPoliciesForUser({
    ...user,
    policies: [{ type: "role", rolename }],
  });

const identify = () => role().identifyUser({ userBody: LOGIN, context });

/** The database cutoff. */
const cutOff = () => role().setPoliciesForUser({ ...user, policies: [] });

/** The cleanup. */
const cleanUp = (overrides: Partial<RequestContext> = {}) =>
  role().deleteUser({ ...user, context: { ...context, ...overrides } });

const EARLIER = {
  validUntil: "2026-11-01T00:00:00Z",
  comment: "an earlier comment",
};
const VERIFIER = "an earlier verifier";

/** A retired login: as the cutoff leaves it, with no password. */
const RETIRED: FakeRole = { canLogin: false, connectionLimit: 0, ...EARLIER };

const ROLES: Record<"active" | "prepared" | "retired", FakeRole> = {
  prepared: {
    canLogin: false,
    connectionLimit: -1,
    password: VERIFIER,
    ...EARLIER,
  },
  active: {
    canLogin: true,
    connectionLimit: -1,
    password: VERIFIER,
    ...EARLIER,
  },
  retired: RETIRED,
};

type State = keyof typeof ROLES | "absent";

/** Puts the grant login in `state`, with or without its grant secret. */
const given = (state: State, secret: "absent" | "filled" = "filled") => {
  if (state !== "absent") db.roles.set(LOGIN, { ...ROLES[state] });
  if (secret === "filled") vault.holding(SECRET, "an earlier password");
};

/** What the revoke path may change: the login, the memberships, what
 * depends on roles and the open sessions in PostgreSQL, and the grant
 * secret's values. */
const everything = () => ({
  roles: structuredClone([...db.roles]),
  memberships: structuredClone(db.memberships),
  objects: structuredClone(db.objects),
  sessions: structuredClone(db.sessions),
  secret: vault.secrets.get(SECRET)?.values.map(String),
});

const RETIRE_STATEMENT = `ALTER ROLE ${LOGIN} NOLOGIN CONNECTION LIMIT 0 PASSWORD NULL`;

/** The login retired in a transaction of its own, which waits for a lock no
 * longer than two seconds. */
const RETIRED_BY_ITS_OWN_TRANSACTION = [
  "BEGIN",
  ["setLockTimeout", "2000ms"],
  ["format", "ALTER ROLE %I NOLOGIN CONNECTION LIMIT 0 PASSWORD NULL", LOGIN],
  RETIRE_STATEMENT,
  "COMMIT",
];

/** The revokes' transaction of a login the manager granted nothing. */
const REVOKES_NOTHING = ["BEGIN", ["managerGrantedRoles", LOGIN], "COMMIT"];

/** The revokes' transaction when the manager granted the login `role`, as
 * `grantor`. */
const REVOKES = (role: string, grantor = "p0_manager") => [
  "BEGIN",
  ["managerGrantedRoles", LOGIN],
  ["format", "REVOKE %I FROM %I GRANTED BY %I", role, LOGIN, grantor],
  `REVOKE ${role} FROM ${LOGIN} GRANTED BY ${grantor}`,
  ["managerGrantedRoles", LOGIN],
  "COMMIT",
];

/** The retire transaction that fails for want of the row, and is rolled
 * back. */
const RETIRE_STALLED = [
  ...RETIRED_BY_ITS_OWN_TRANSACTION.slice(0, -1),
  "ROLLBACK",
];

/** The two looks that end a session and see it gone. */
const SESSIONS_ENDED = [
  ["endSessions", LOGIN],
  ["countSessions", LOGIN],
  "wait 200",
  ["endSessions", LOGIN],
  ["countSessions", LOGIN],
];

describe("setPoliciesForUser with no policies", () => {
  it("takes back the manager's grants in a transaction, retires the login in a second, then ends its sessions, then counts that none is left", async () => {
    given("active");
    db.roles.set(OTHER_LOGIN, { ...ROLES.active });
    db.memberships.push(
      { role: "analyst", member: LOGIN, byManager: true },
      { role: "dba_team", member: LOGIN, byManager: false },
      { role: "analyst", member: OTHER_LOGIN, byManager: true }
    );
    db.sessions.push(
      { usename: LOGIN },
      { usename: OTHER_LOGIN },
      { usename: LOGIN }
    );

    await expect(cutOff()).resolves.toBe(null);

    expect(journal).toEqual([
      `getSecretValue ${MANAGER_SECRET_ARN}`,
      ["login", LOGIN],
      ...REVOKES("analyst"),
      ...RETIRED_BY_ITS_OWN_TRANSACTION,
      ...SESSIONS_ENDED,
      "close",
    ]);
    expect(everything()).toEqual({
      roles: [
        [
          LOGIN,
          {
            canLogin: false,
            connectionLimit: 0,
            validUntil: "2026-11-01T00:00:00Z",
            comment: "an earlier comment",
          },
        ],
        [OTHER_LOGIN, ROLES.active],
      ],
      memberships: [
        { role: "dba_team", member: LOGIN, byManager: false },
        { role: "analyst", member: OTHER_LOGIN, byManager: true },
      ],
      objects: [],
      sessions: [{ usename: OTHER_LOGIN }],
      secret: ["an earlier password"],
    });
  });

  it("with no login, succeeds without a write", async () => {
    given("absent");
    const before = everything();

    await expect(cutOff()).resolves.toBe(null);

    expect(everything()).toEqual(before);
    expect(journal).toEqual([
      `getSecretValue ${MANAGER_SECRET_ARN}`,
      ["login", LOGIN],
      "close",
    ]);
  });

  it.each(["prepared", "active", "retired"] as const)(
    "leaves a %s login retired, and run again changes nothing",
    async (state) => {
      given(state);
      db.sessions.push({ usename: LOGIN });

      await expect(cutOff()).resolves.toBe(null);

      const after = everything();
      expect(after).toEqual({
        roles: [[LOGIN, RETIRED]],
        memberships: [],
        objects: [],
        sessions: [],
        secret: ["an earlier password"],
      });
      await expect(identify()).resolves.toBe(LOGIN);
      db.calls.length = 0;

      await expect(cutOff()).resolves.toBe(null);

      expect(everything()).toEqual(after);
      expect(db.calls).toEqual([
        ["login", LOGIN],
        ...REVOKES_NOTHING,
        ...RETIRED_BY_ITS_OWN_TRANSACTION,
        ["endSessions", LOGIN],
        ["countSessions", LOGIN],
        ["endSessions", LOGIN],
        ["countSessions", LOGIN],
        "close",
      ]);
    }
  );

  it("looks again after a wait, and ends again, while a session it ended is still going", async () => {
    given("active");
    db.sessions.push({ usename: LOGIN, outlives: 2 }, { usename: LOGIN });

    await expect(cutOff()).resolves.toBe(null);

    expect(journal.slice(journal.lastIndexOf("COMMIT"))).toEqual([
      "COMMIT",
      ["endSessions", LOGIN],
      ["countSessions", LOGIN],
      "wait 200",
      ["endSessions", LOGIN],
      ["countSessions", LOGIN],
      "wait 200",
      ["endSessions", LOGIN],
      ["countSessions", LOGIN],
      "close",
    ]);
    expect(db.sessions).toEqual([]);
    expect(log.lines.join("")).toContain('"sessionsEnded":2');
  });

  it("ends a session that shows only after the first look, as one does that signed in just before the commit", async () => {
    given("active");
    const late = [{ usename: LOGIN }];
    wait = async (ms) => {
      journal.push(`wait ${ms}`);
      db.sessions.push(...late.splice(0));
    };

    await expect(cutOff()).resolves.toBe(null);

    expect(journal.slice(journal.lastIndexOf("COMMIT"))).toEqual([
      "COMMIT",
      ["endSessions", LOGIN],
      ["countSessions", LOGIN],
      "wait 200",
      ["endSessions", LOGIN],
      ["countSessions", LOGIN],
      "close",
    ]);
    expect(db.sessions).toEqual([]);
    expect(log.lines.join("")).toContain('"sessionsEnded":1');
  });

  it("throws as unavailable when a session will not end, leaves the login retired, and succeeds once the session is gone", async () => {
    given("active");
    db.memberships.push({ role: "analyst", member: LOGIN, byManager: true });
    db.sessions.push(
      { usename: LOGIN, outlives: Infinity },
      { usename: LOGIN }
    );

    await expect(dataOf(cutOff())).resolves.toEqual({
      type: "upstream_unavailable",
      message:
        "The grant login is disabled, but some of its sessions have not ended yet. Try again in a moment.",
      payload: { login: LOGIN, sessions: 1, step: "end_sessions" },
    });

    expect(journal.slice(journal.lastIndexOf("COMMIT"))).toEqual([
      "COMMIT",
      ["endSessions", LOGIN],
      ["countSessions", LOGIN],
      ...Array.from({ length: 9 }).flatMap(() => [
        "wait 200",
        ["endSessions", LOGIN],
        ["countSessions", LOGIN],
      ]),
      "close",
    ]);
    expect(db.roles.get(LOGIN)).toEqual(RETIRED);
    expect(db.memberships).toEqual([]);
    await expect(identify()).resolves.toBe(LOGIN);

    db.sessions.length = 0;
    await expect(cutOff()).resolves.toBe(null);

    expect(db.roles.get(LOGIN)).toEqual(RETIRED);
  });

  it.each(["endSessions", "countSessions"] as const)(
    "when PostgreSQL refuses %s, leaves the login retired, and the next call finishes the cutoff",
    async (statement) => {
      given("active");
      db.memberships.push({ role: "analyst", member: LOGIN, byManager: true });
      db.sessions.push({ usename: LOGIN });
      const before = everything();
      const stop = db.failOn(statement, pgError("57014"));

      const data = await dataOf(cutOff());

      expect(data.type).toBe("upstream_unavailable");
      expect(data.payload).toEqual({ sqlState: "57014", step: "end_sessions" });
      expect(everything()).toEqual({
        ...before,
        roles: [[LOGIN, RETIRED]],
        memberships: [],
        sessions: [
          {
            usename: LOGIN,
            ...(statement === "countSessions" ? { signalled: true } : {}),
          },
        ],
      });
      await expect(identify()).resolves.toBe(LOGIN);

      stop();
      await expect(cutOff()).resolves.toBe(null);

      expect(everything()).toEqual({
        ...before,
        roles: [[LOGIN, RETIRED]],
        memberships: [],
        sessions: [],
      });
    }
  );

  describe("when a session of the login stalls the retiring ALTER ROLE", () => {
    // A session of the login that holds the login's row, as one does that
    // ran ALTER ROLE on itself in a transaction it keeps open. The ALTER ROLE
    // waits for the row, until the lock timeout. The first `times` attempts
    // stall.
    const stalledBy = (sqlState: string, times = 1) => {
      let left = times;
      const stop = db.failOn(RETIRE_STATEMENT, () => {
        if (--left === 0) stop();
        return pgError(sqlState);
      });
      return stop;
    };

    const analystHeld = () => {
      given("active");
      db.memberships.push({ role: "analyst", member: LOGIN, byManager: true });
      db.sessions.push({ usename: LOGIN });
    };

    it.each(["55P03", "57014"])(
      "has taken back the manager's grants, ends the login's sessions, retries, and finishes the cutoff (SQLSTATE %s)",
      async (sqlState) => {
        analystHeld();
        stalledBy(sqlState);

        await expect(cutOff()).resolves.toBe(null);

        expect(journal.slice(journal.indexOf("BEGIN"))).toEqual([
          ...REVOKES("analyst"),
          ...RETIRE_STALLED,
          ["endSessions", LOGIN],
          ...RETIRED_BY_ITS_OWN_TRANSACTION,
          ...SESSIONS_ENDED,
          "close",
        ]);
        expect(everything()).toEqual({
          roles: [[LOGIN, RETIRED]],
          memberships: [],
          objects: [],
          sessions: [],
          secret: ["an earlier password"],
        });
      }
    );

    it("ends the login's sessions between attempts, and finishes the cutoff on the third", async () => {
      analystHeld();
      stalledBy("55P03", 2);

      await expect(cutOff()).resolves.toBe(null);

      expect(journal.slice(journal.indexOf("BEGIN"))).toEqual([
        ...REVOKES("analyst"),
        ...RETIRE_STALLED,
        ["endSessions", LOGIN],
        ...RETIRE_STALLED,
        ["endSessions", LOGIN],
        ...RETIRED_BY_ITS_OWN_TRANSACTION,
        ...SESSIONS_ENDED,
        "close",
      ]);
      expect(everything()).toEqual({
        roles: [[LOGIN, RETIRED]],
        memberships: [],
        objects: [],
        sessions: [],
        secret: ["an earlier password"],
      });
    });

    it("throws when all three attempts stall, with the memberships taken back, the login active and its sessions ended, and the next call finishes the cutoff", async () => {
      analystHeld();
      const stop = stalledBy("55P03", Infinity);

      const data = await dataOf(cutOff());

      expect(data.type).toBe("upstream_unavailable");
      expect(data.payload).toEqual({ sqlState: "55P03", step: "retire_login" });
      expect(journal.slice(journal.indexOf("BEGIN"))).toEqual([
        ...REVOKES("analyst"),
        ...RETIRE_STALLED,
        ["endSessions", LOGIN],
        ...RETIRE_STALLED,
        ["endSessions", LOGIN],
        ...RETIRE_STALLED,
        ...SESSIONS_ENDED,
        "close",
      ]);
      expect(everything()).toEqual({
        roles: [[LOGIN, ROLES.active]],
        memberships: [],
        objects: [],
        sessions: [],
        secret: ["an earlier password"],
      });
      await expect(identify()).resolves.toBe(LOGIN);

      stop();
      await expect(cutOff()).resolves.toBe(null);

      expect(db.roles.get(LOGIN)).toEqual(RETIRED);
      expect(db.sessions).toEqual([]);
    });

    it("does not retry when PostgreSQL refuses for another reason, and still has taken back the grants and ended the sessions", async () => {
      analystHeld();
      db.failOn(RETIRE_STATEMENT, pgError("42501"));

      const data = await dataOf(cutOff());

      expect(data.type).toBe("insufficient_privileges");
      expect(journal.slice(journal.indexOf("BEGIN"))).toEqual([
        ...REVOKES("analyst"),
        ...RETIRE_STALLED,
        ...SESSIONS_ENDED,
        "close",
      ]);
      expect(everything()).toEqual({
        roles: [[LOGIN, ROLES.active]],
        memberships: [],
        objects: [],
        sessions: [],
        secret: ["an earlier password"],
      });
    });
  });

  it("when PostgreSQL refuses COMMIT of the revokes and of the retirement, throws the retirement's error, leaves the login active with its roles, and ends its sessions", async () => {
    given("active");
    db.memberships.push({ role: "analyst", member: LOGIN, byManager: true });
    db.sessions.push({ usename: LOGIN });
    const before = everything();
    db.failOn("COMMIT", pgError("42501"));

    const data = await dataOf(cutOff());

    expect(data.type).toBe("insufficient_privileges");
    expect(everything()).toEqual({ ...before, sessions: [] });
  });

  describe("when more than one step fails", () => {
    const held = () => {
      given("active");
      db.memberships.push({ role: "analyst", member: LOGIN, byManager: true });
      db.sessions.push({ usename: LOGIN });
    };

    it("throws the retirement's error when the revokes fail too, and still ends the sessions", async () => {
      db = fakeDatabase({ ignoresRevoke: true }, journal);
      held();
      db.failOn(RETIRE_STATEMENT, pgError("42501"));

      const data = await dataOf(cutOff());

      expect(data.type).toBe("insufficient_privileges");
      expect(db.roles.get(LOGIN)).toEqual(ROLES.active);
      expect(db.memberships).toEqual([
        { role: "analyst", member: LOGIN, byManager: true },
      ]);
      expect(db.sessions).toEqual([]);
    });

    it("throws the revokes' error when the sessions will not end either, after the login is retired", async () => {
      db = fakeDatabase({ ignoresRevoke: true }, journal);
      held();
      db.failOn("endSessions", pgError("57014"));

      const data = await dataOf(cutOff());

      expect(data.type).toBe("dependency_violation");
      expect(data.payload).toEqual({ login: LOGIN, step: "revoke_roles" });
      expect(db.roles.get(LOGIN)).toEqual(RETIRED);
    });

    it("throws the retirement's error when the sessions will not end either", async () => {
      held();
      db.failOn(RETIRE_STATEMENT, pgError("42501"));
      db.failOn("endSessions", pgError("57014"));

      const data = await dataOf(cutOff());

      expect(data.type).toBe("insufficient_privileges");
      expect(db.memberships).toEqual([]);
    });

    it("retires the login and ends its sessions when the revokes fail, throws their error, and the next call finishes them", async () => {
      held();
      const stop = db.failOn("REVOKE", pgError("42501"));

      const data = await dataOf(cutOff());

      expect(data.type).toBe("insufficient_privileges");
      expect(journal.slice(journal.indexOf("BEGIN"))).toEqual([
        "BEGIN",
        ["managerGrantedRoles", LOGIN],
        [
          "format",
          "REVOKE %I FROM %I GRANTED BY %I",
          "analyst",
          LOGIN,
          "p0_manager",
        ],
        `REVOKE analyst FROM ${LOGIN} GRANTED BY p0_manager`,
        "ROLLBACK",
        ...RETIRED_BY_ITS_OWN_TRANSACTION,
        ...SESSIONS_ENDED,
        "close",
      ]);
      expect(everything()).toEqual({
        roles: [[LOGIN, RETIRED]],
        memberships: [{ role: "analyst", member: LOGIN, byManager: true }],
        objects: [],
        sessions: [],
        secret: ["an earlier password"],
      });

      stop();
      await expect(cutOff()).resolves.toBe(null);

      expect(db.memberships).toEqual([]);
    });
  });

  describe("when taking back the manager's grants fails", () => {
    it("leaves the login retired and its sessions ended, throws, and the next call finishes the cutoff", async () => {
      given("active");
      db.memberships.push({ role: "analyst", member: LOGIN, byManager: true });
      db.sessions.push({ usename: LOGIN });
      const stop = db.failOn("REVOKE", pgError("57014"));

      const data = await dataOf(cutOff());

      expect(data.type).toBe("upstream_unavailable");
      expect(data.payload).toEqual({ sqlState: "57014", step: "revoke_roles" });
      expect(db.roles.get(LOGIN)).toEqual(RETIRED);
      expect(db.sessions).toEqual([]);
      expect(db.memberships).toEqual([
        { role: "analyst", member: LOGIN, byManager: true },
      ]);
      await expect(identify()).resolves.toBe(LOGIN);

      stop();
      await expect(cutOff()).resolves.toBe(null);

      expect(db.memberships).toEqual([]);
    });

    it("revokes each membership as the grantor it records, from PostgreSQL 16", async () => {
      given("active");
      db.memberships.push(
        {
          role: "analyst",
          member: LOGIN,
          byManager: true,
          grantor: "it_group",
        },
        { role: "analyst", member: LOGIN, byManager: true },
        { role: "reporting", member: LOGIN, byManager: true }
      );

      await cutOff();

      expect(
        db.calls.filter(
          (call) => typeof call === "string" && call.startsWith("REVOKE")
        )
      ).toEqual([
        `REVOKE analyst FROM ${LOGIN} GRANTED BY it_group`,
        `REVOKE analyst FROM ${LOGIN} GRANTED BY p0_manager`,
        `REVOKE reporting FROM ${LOGIN} GRANTED BY p0_manager`,
      ]);
      expect(db.memberships).toEqual([]);
    });

    it("revokes without naming the grantor before PostgreSQL 16", async () => {
      db = fakeDatabase({ hasGrantOptions: false }, journal);
      given("active");
      db.memberships.push({ role: "analyst", member: LOGIN, byManager: true });

      await cutOff();

      expect(
        db.calls.filter(
          (call) => typeof call === "string" && call.startsWith("REVOKE")
        )
      ).toEqual([`REVOKE analyst FROM ${LOGIN}`]);
      expect(db.memberships).toEqual([]);
    });

    it.each([true, false])(
      "when a REVOKE removes nothing, throws dependency_violation with only the login, after the sessions are ended, and leaves the login retired (PostgreSQL 16 or later: %s)",
      async (hasGrantOptions) => {
        db = fakeDatabase({ hasGrantOptions, ignoresRevoke: true }, journal);
        given("active");
        db.memberships.push({
          role: "analyst",
          member: LOGIN,
          byManager: true,
        });
        db.sessions.push({ usename: LOGIN });

        const data = await dataOf(cutOff());

        expect(data.type).toBe("dependency_violation");
        expect(data.payload).toEqual({ login: LOGIN, step: "revoke_roles" });
        expect(db.roles.get(LOGIN)).toEqual(RETIRED);
        expect(db.sessions).toEqual([]);
        expect(db.memberships).toEqual([
          { role: "analyst", member: LOGIN, byManager: true },
        ]);
      }
    );
  });
});

/** Something the grant login owns in `database`. */
const owned = (database: string, name: string): FakeObject => ({
  database,
  name,
  owner: LOGIN,
  grantees: [],
});

const HAND_OVER = [
  "BEGIN",
  ["format", "REASSIGN OWNED BY %I TO %I", LOGIN, "analyst"],
  `REASSIGN OWNED BY ${LOGIN} TO analyst`,
  ["format", "DROP OWNED BY %I", LOGIN],
  `DROP OWNED BY ${LOGIN}`,
  "COMMIT",
  "close",
];

/** The looks for a session the cutoff missed, before the login is dropped. */
const LAST_LOOKS = [
  ["endSessions", LOGIN],
  ["countSessions", LOGIN],
  "wait 200",
  ["endSessions", LOGIN],
  ["countSessions", LOGIN],
];

describe("deleteUser", () => {
  it("ends a session the cutoff missed before it drops the login", async () => {
    given("retired");
    db.sessions.push({ usename: LOGIN }, { usename: OTHER_LOGIN });

    await expect(cleanUp()).resolves.toBe(null);

    expect(db.sessions).toEqual([{ usename: OTHER_LOGIN }]);
    expect([...db.roles]).toEqual([]);
  });

  it("does not drop a login whose session will not end, so that the next call still finds both", async () => {
    given("retired");
    db.sessions.push({ usename: LOGIN, outlives: 100 });

    await expect(dataOf(cleanUp())).resolves.toEqual({
      type: "upstream_unavailable",
      message:
        "The grant login is disabled, but some of its sessions have not ended yet. Try again in a moment.",
      payload: { login: LOGIN, sessions: 1, step: "end_sessions" },
    });

    expect(db.roles.get(LOGIN)).toEqual(RETIRED);
    expect(db.calls).not.toContain(`DROP ROLE ${LOGIN}`);
    await expect(identify()).resolves.toBe(LOGIN);
  });

  it("deletes the grant secret, takes the login's privileges, hands over what it owns in each database, then drops it", async () => {
    given("retired");
    db.objects.push(
      owned("orders", "orders.public.drafts"),
      {
        database: "orders",
        name: "orders.public.invoices",
        owner: "billing",
        grantees: [LOGIN, "analyst"],
      },
      owned("postgres", "postgres.public.notes")
    );

    await expect(cleanUp()).resolves.toBe(null);

    expect(journal).toEqual([
      `getSecretValue ${MANAGER_SECRET_ARN}`,
      ["login", LOGIN],
      ["isGrantableRole", "analyst"],
      `deleteSecret ${SECRET}`,
      "hasGrantOptions",
      ["format", "GRANT %I TO current_user WITH INHERIT TRUE", LOGIN],
      `GRANT ${LOGIN} TO current_user WITH INHERIT TRUE`,
      "connectableDatabases",
      "BEGIN",
      ["format", "REASSIGN OWNED BY %I TO %I", LOGIN, "analyst"],
      `REASSIGN OWNED BY ${LOGIN} TO analyst`,
      ["format", "DROP OWNED BY %I", LOGIN],
      `DROP OWNED BY ${LOGIN}`,
      "COMMIT",
      "close",
      "BEGIN",
      ["format", "REASSIGN OWNED BY %I TO %I", LOGIN, "analyst"],
      `REASSIGN OWNED BY ${LOGIN} TO analyst`,
      ["format", "DROP OWNED BY %I", LOGIN],
      `DROP OWNED BY ${LOGIN}`,
      "COMMIT",
      "close",
      ...LAST_LOOKS,
      ["format", "DROP ROLE %I", LOGIN],
      `DROP ROLE ${LOGIN}`,
      "close",
    ]);
    expect(db.signIns.map(({ database }) => database)).toEqual([
      "postgres",
      "orders",
      "postgres",
    ]);
    expect(everything()).toEqual({
      roles: [],
      memberships: [],
      objects: [
        {
          database: "orders",
          name: "orders.public.drafts",
          owner: "analyst",
          grantees: [],
        },
        {
          database: "orders",
          name: "orders.public.invoices",
          owner: "billing",
          grantees: ["analyst"],
        },
        {
          database: "postgres",
          name: "postgres.public.notes",
          owner: "analyst",
          grantees: [],
        },
      ],
      sessions: [],
      secret: undefined,
    });
    await expect(identify()).resolves.toBe(null);
  });

  it("reads the manager's credential once, and signs in to every database with it", async () => {
    given("retired");

    await cleanUp();

    expect(vault.reads.map(({ ref }) => ref)).toEqual([MANAGER_SECRET_ARN]);
    expect(db.signIns).toEqual(
      ["postgres", "orders", "postgres"].map((database) => ({
        host: "orders.cluster-abc123.us-east-1.rds.amazonaws.com",
        port: 5432,
        database,
        username: "p0_manager",
        password: "correct-horse-battery-staple",
      }))
    );
  });

  it("deletes the grant secret in the request's region", async () => {
    given("retired");

    await cleanUp({ secrets: { manager: "aws", region: "eu-west-1" } });

    expect(vault.regions).toEqual(["eu-west-1"]);
    expect(vault.secrets.has(SECRET)).toBe(false);
  });

  it("takes the login's privileges without an option before PostgreSQL 16", async () => {
    db = fakeDatabase({ hasGrantOptions: false }, journal);
    given("retired");
    db.objects.push(owned("orders", "orders.public.drafts"));

    await expect(cleanUp()).resolves.toBe(null);

    expect(db.calls.slice(2, 5)).toEqual([
      "hasGrantOptions",
      ["format", "GRANT %I TO current_user", LOGIN],
      `GRANT ${LOGIN} TO current_user`,
    ]);
    expect([...db.roles]).toEqual([]);
    expect(db.memberships).toEqual([]);
  });

  it.each(["absent", "filled"] as const)(
    "with no login and its grant secret %s, leaves no grant secret and succeeds",
    async (secret) => {
      given("absent", secret);

      await expect(cleanUp()).resolves.toBe(null);

      expect(journal).toEqual([
        `getSecretValue ${MANAGER_SECRET_ARN}`,
        ["login", LOGIN],
        `deleteSecret ${SECRET}`,
        "close",
      ]);
      expect(everything()).toEqual({
        roles: [],
        memberships: [],
        objects: [],
        sessions: [],
        secret: undefined,
      });
    }
  );

  it.each(["prepared", "active"] as const)(
    "refuses a %s login, which has not been cut off, and changes nothing",
    async (state) => {
      given(state);
      db.objects.push(owned("orders", "orders.public.drafts"));
      const before = everything();

      await expect(dataOf(cleanUp())).resolves.toEqual({
        type: "dependency_violation",
        message:
          "The grant login has not been cut off. The connector drops a login only after its database cutoff.",
        payload: { login: LOGIN, state, step: "read_login" },
      });

      expect(everything()).toEqual(before);
      expect(journal).toEqual([
        `getSecretValue ${MANAGER_SECRET_ARN}`,
        ["login", LOGIN],
        "close",
      ]);
    }
  );

  describe("with an objectOwner that is not a grantable role", () => {
    const UNGRANTABLE = { objectOwner: "postgres" };

    it("refuses a login that owns an object, before it writes anything, and keeps the object", async () => {
      given("retired");
      db.objects.push(owned("orders", "orders.public.drafts"));
      const before = everything();

      await expect(dataOf(cleanUp(UNGRANTABLE))).resolves.toEqual({
        type: "validation_error",
        message: "The role postgres is not a grantable role of this target.",
        payload: {
          login: LOGIN,
          rolename: "postgres",
          step: "read_ownership",
        },
      });

      expect(everything()).toEqual(before);
      expect(journal).toEqual([
        `getSecretValue ${MANAGER_SECRET_ARN}`,
        ["login", LOGIN],
        ["isGrantableRole", "postgres"],
        ["ownsAnything", LOGIN],
        "close",
      ]);
    });

    it("refuses a login that owns an object in a database the manager cannot connect to", async () => {
      db = fakeDatabase(
        {
          databases: ["billing", "orders", "postgres"],
          closedDatabases: ["billing"],
        },
        journal
      );
      given("retired");
      db.objects.push(owned("billing", "billing.public.ledger"));
      const before = everything();

      await expect(dataOf(cleanUp(UNGRANTABLE))).resolves.toMatchObject({
        type: "validation_error",
        payload: { login: LOGIN, rolename: "postgres" },
      });

      expect(everything()).toEqual(before);
    });

    it("cleans up a login that owns nothing: it drops the privileges the login was granted, in each database, and the login", async () => {
      given("retired");
      db.objects.push({
        database: "orders",
        name: "orders.public.invoices",
        owner: "billing",
        grantees: [LOGIN, "analyst"],
      });

      await expect(cleanUp(UNGRANTABLE)).resolves.toBe(null);

      expect(journal).toEqual([
        `getSecretValue ${MANAGER_SECRET_ARN}`,
        ["login", LOGIN],
        ["isGrantableRole", "postgres"],
        ["ownsAnything", LOGIN],
        `deleteSecret ${SECRET}`,
        "hasGrantOptions",
        ["format", "GRANT %I TO current_user WITH INHERIT TRUE", LOGIN],
        `GRANT ${LOGIN} TO current_user WITH INHERIT TRUE`,
        ...LAST_LOOKS,
        "connectableDatabases",
        ...["orders", "postgres"].flatMap(() => [
          "BEGIN",
          ["ownsHere", LOGIN],
          ["format", "DROP OWNED BY %I", LOGIN],
          `DROP OWNED BY ${LOGIN}`,
          "COMMIT",
          "close",
        ]),
        ...LAST_LOOKS,
        ["format", "DROP ROLE %I", LOGIN],
        `DROP ROLE ${LOGIN}`,
        "close",
      ]);
      expect(db.calls).not.toContain(`REASSIGN OWNED BY ${LOGIN} TO postgres`);
      expect(everything()).toEqual({
        roles: [],
        memberships: [],
        objects: [
          {
            database: "orders",
            name: "orders.public.invoices",
            owner: "billing",
            grantees: ["analyst"],
          },
        ],
        sessions: [],
        secret: undefined,
      });
    });

    it("refuses, and drops nothing, when the login comes to own something after the first read", async () => {
      given("retired");
      // A session that outlived the cutoff creates a table while the cleanup
      // waits for it to end.
      db.sessions.push({ usename: LOGIN, outlives: 1 });
      wait = async (ms) => {
        journal.push(`wait ${ms}`);
        if (db.objects.length === 0) {
          db.objects.push(owned("orders", "orders.public.late"));
        }
      };

      await expect(dataOf(cleanUp(UNGRANTABLE))).resolves.toEqual({
        type: "validation_error",
        message: "The role postgres is not a grantable role of this target.",
        payload: {
          login: LOGIN,
          rolename: "postgres",
          step: "release_owned",
          database: "orders",
        },
      });

      expect(db.objects).toEqual([owned("orders", "orders.public.late")]);
      expect(db.calls).not.toContain(`DROP OWNED BY ${LOGIN}`);
      expect(db.roles.get(LOGIN)).toEqual(RETIRED);
    });

    it("lets a revoke finish after a grant that failed because its role is not grantable", async () => {
      const ungrantable = { ...context, objectOwner: "postgres" };
      await role().provisionUser({ userBody: LOGIN, context: ungrantable });
      await expect(
        dataOf(
          role().setPoliciesForUser({
            ...user,
            policies: [{ type: "role", rolename: "postgres" }],
            context: ungrantable,
          })
        )
      ).resolves.toMatchObject({ type: "validation_error" });
      await expect(identify()).resolves.toBe(LOGIN);

      await expect(
        role().setPoliciesForUser({
          ...user,
          policies: [],
          context: ungrantable,
        })
      ).resolves.toBe(null);
      await expect(cleanUp(UNGRANTABLE)).resolves.toBe(null);

      await expect(identify()).resolves.toBe(null);
      expect(vault.secrets.has(SECRET)).toBe(false);
      expect([...db.roles]).toEqual([]);
    });
  });

  it("finishes a retired login whose grant secret is already gone", async () => {
    given("retired", "absent");
    db.objects.push(owned("orders", "orders.public.drafts"));

    await expect(identify()).resolves.toBe(LOGIN);
    await expect(cleanUp()).resolves.toBe(null);

    expect(journal).toContain(`deleteSecret ${SECRET}`);
    expect(everything()).toEqual({
      roles: [],
      memberships: [],
      objects: [
        {
          database: "orders",
          name: "orders.public.drafts",
          owner: "analyst",
          grantees: [],
        },
      ],
      sessions: [],
      secret: undefined,
    });
  });

  describe("with a database the manager cannot connect to", () => {
    beforeEach(() => {
      db = fakeDatabase(
        {
          databases: ["billing", "orders", "postgres"],
          closedDatabases: ["billing"],
        },
        journal
      );
      given("retired");
      db.objects.push(owned("orders", "orders.public.drafts"));
    });

    it("hands over in every other database, and drops a login that owns nothing in that one", async () => {
      await expect(cleanUp()).resolves.toBe(null);

      expect(db.signIns.map(({ database }) => database)).toEqual([
        "postgres",
        "orders",
        "postgres",
      ]);
      expect([...db.roles]).toEqual([]);
      expect(db.objects).toEqual([
        {
          database: "orders",
          name: "orders.public.drafts",
          owner: "analyst",
          grantees: [],
        },
      ]);
    });

    it("cannot drop a login that owns something in that one, leaves it retired, and finishes once that is dealt with", async () => {
      db.objects.push(owned("billing", "billing.public.ledger"));

      await expect(dataOf(cleanUp())).resolves.toEqual({
        type: "dependency_violation",
        message:
          "PostgreSQL refused the operation because other objects depend on the role.",
        payload: { sqlState: "2BP01", step: "drop_login" },
      });

      expect(everything()).toEqual({
        roles: [[LOGIN, RETIRED]],
        // The grant of the login to the manager, which goes with the login.
        memberships: [{ role: LOGIN, member: "p0_manager", byManager: true }],
        objects: [
          {
            database: "orders",
            name: "orders.public.drafts",
            owner: "analyst",
            grantees: [],
          },
          {
            database: "billing",
            name: "billing.public.ledger",
            owner: LOGIN,
            grantees: [],
          },
        ],
        sessions: [],
        secret: undefined,
      });
      await expect(identify()).resolves.toBe(LOGIN);

      db.objects.pop();
      await expect(cleanUp()).resolves.toBe(null);

      expect([...db.roles]).toEqual([]);
      expect(db.memberships).toEqual([]);
    });
  });

  describe("when a step fails", () => {
    const DONE = {
      roles: [],
      memberships: [],
      objects: [
        {
          database: "orders",
          name: "orders.public.drafts",
          owner: "analyst",
          grantees: [],
        },
        {
          database: "postgres",
          name: "postgres.public.notes",
          owner: "analyst",
          grantees: [],
        },
      ],
      sessions: [],
      secret: undefined,
    };
    const ORDERS = owned("orders", "orders.public.drafts");
    const NOTES = owned("postgres", "postgres.public.notes");
    const TAKEN = { role: LOGIN, member: "p0_manager", byManager: true };
    const HANDED_OVER = { ...ORDERS, owner: "analyst" };

    beforeEach(() => {
      given("retired");
      db.objects.push({ ...ORDERS }, { ...NOTES });
    });

    it("the deletion of the grant secret, it changes nothing, and the next call finishes the cleanup", async () => {
      const before = everything();
      vault.state.failNextDelete = new UnauthorizedError("aws");

      await expect(dataOf(cleanUp())).resolves.toEqual({
        type: "insufficient_privileges",
        message:
          "Secrets Manager refused to let the connector delete the grant secret. Give the connector's role secretsmanager:DeleteSecret on the secrets under p0/postgres-ai/<vpc id>/.",
        payload: { step: "delete_secret" },
      });

      expect(everything()).toEqual(before);
      expect(db.calls).toEqual([
        ["login", LOGIN],
        ["isGrantableRole", "analyst"],
        "close",
      ]);

      await expect(cleanUp()).resolves.toBe(null);

      expect(everything()).toEqual(DONE);
    });

    it.each([
      [
        "the grant of the login to the manager",
        "GRANT p0v_",
        undefined,
        { memberships: [], objects: [ORDERS, NOTES] },
        { step: "take_privileges" },
      ],
      [
        "the reassign in the first database",
        "REASSIGN OWNED",
        "orders",
        { memberships: [TAKEN], objects: [ORDERS, NOTES] },
        { step: "release_owned", database: "orders" },
      ],
      [
        "the commit in the first database",
        "COMMIT",
        "orders",
        { memberships: [TAKEN], objects: [ORDERS, NOTES] },
        { step: "release_owned", database: "orders" },
      ],
      [
        "the drop of what it owns in the second database",
        "DROP OWNED",
        "postgres",
        { memberships: [TAKEN], objects: [HANDED_OVER, NOTES] },
        { step: "release_owned", database: "postgres" },
      ],
      [
        "the drop of the login",
        "DROP ROLE",
        undefined,
        { memberships: [TAKEN], objects: DONE.objects },
        { step: "drop_login" },
      ],
    ])(
      "%s, the login stays retired and found, and the next call finishes the cleanup",
      async (_, statement, database, left, where) => {
        const stop = db.failOn(statement, pgError("57014"), database);

        const data = await dataOf(cleanUp());

        expect(data.type).toBe("upstream_unavailable");
        expect(data.payload).toEqual({ sqlState: "57014", ...where });
        expect(everything()).toEqual({
          roles: [[LOGIN, RETIRED]],
          sessions: [],
          secret: undefined,
          ...left,
        });
        await expect(identify()).resolves.toBe(LOGIN);

        stop();
        journal.length = 0;
        await expect(cleanUp()).resolves.toBe(null);

        expect(everything()).toEqual(DONE);
        expect(journal).toEqual([
          `getSecretValue ${MANAGER_SECRET_ARN}`,
          ["login", LOGIN],
          ["isGrantableRole", "analyst"],
          `deleteSecret ${SECRET}`,
          "hasGrantOptions",
          ["format", "GRANT %I TO current_user WITH INHERIT TRUE", LOGIN],
          `GRANT ${LOGIN} TO current_user WITH INHERIT TRUE`,
          "connectableDatabases",
          ...HAND_OVER,
          ...HAND_OVER,
          ...LAST_LOOKS,
          ["format", "DROP ROLE %I", LOGIN],
          `DROP ROLE ${LOGIN}`,
          "close",
        ]);
      }
    );
  });
});

describe("a grant's whole life, from provisionUser to deleteUser", () => {
  /** A revoke, as the P0 control plane drives it. */
  const revoke = async () => {
    if ((await identify()) !== null) await cutOff();
    if ((await identify()) !== null) await cleanUp();
  };

  it("ends with no login, no grant secret, and the manager a member of nothing", async () => {
    await provision();
    await approve("analyst");
    db.sessions.push({ usename: LOGIN });
    db.objects.push(owned("orders", "orders.public.drafts"));
    expect(db.memberships).toEqual([
      {
        role: "analyst",
        member: LOGIN,
        byManager: true,
        grantor: "p0_manager",
      },
    ]);

    await revoke();

    expect(everything()).toEqual({
      roles: [],
      memberships: [],
      objects: [
        {
          database: "orders",
          name: "orders.public.drafts",
          owner: "analyst",
          grantees: [],
        },
      ],
      sessions: [],
      secret: undefined,
    });
    await expect(identify()).resolves.toBe(null);
  });

  it("revoked again, changes nothing and reaches PostgreSQL only to look the login up", async () => {
    await provision();
    await approve("analyst");
    await revoke();
    const after = everything();
    db.calls.length = 0;

    await revoke();
    await expect(cutOff()).resolves.toBe(null);
    await expect(cleanUp()).resolves.toBe(null);

    expect(everything()).toEqual(after);
    expect(db.calls).toEqual([
      ["login", LOGIN],
      "close",
      ["login", LOGIN],
      "close",
      ["login", LOGIN],
      "close",
      ["login", LOGIN],
      "close",
    ]);
  });

  it("never reads the grant secret's value", async () => {
    await provision();
    await approve("analyst");
    await revoke();

    expect([...new Set(vault.reads.map(({ ref }) => ref))]).toEqual([
      MANAGER_SECRET_ARN,
    ]);
  });
});

describe("what the revoke path shows", () => {
  const HIDDEN = [
    VERIFIER,
    "an earlier password",
    "ALTER ROLE",
    "REVOKE",
    "REASSIGN OWNED",
    "DROP OWNED",
    "DROP ROLE",
    "pg_terminate_backend",
    "current_user",
  ];

  /** Everything a call shows: the error it failed with, with its causes,
   * and the log. */
  const shownBy = async (call: Promise<unknown>) => {
    const error = await call.then(
      () => undefined,
      (e: unknown) => e
    );
    return `${inspect(error, { depth: 10 })}\n${log.lines.join("")}`;
  };

  const expectNothingHiddenIn = (shown: string) => {
    for (const hidden of HIDDEN) expect(shown).not.toContain(hidden);
  };

  it("logs the state a cutoff came from, the roles it revoked and the sessions it ended, and no statement", async () => {
    given("active");
    db.memberships.push({ role: "analyst", member: LOGIN, byManager: true });
    db.sessions.push({ usename: LOGIN }, { usename: LOGIN });

    const shown = await shownBy(cutOff());

    expect(shown).toContain(
      "cut off the grant login and confirmed that none of its sessions is left"
    );
    expect(shown).toContain(
      '"from":"active","revoked":["analyst"],"sessionsEnded":2'
    );
    expect(shown).toContain(`"login":"${LOGIN}"`);
    expectNothingHiddenIn(shown);
  });

  it("logs the state a cleanup came from, the new owner and the databases, and no statement or secret value", async () => {
    given("retired");

    const shown = await shownBy(cleanUp());

    expect(shown).toContain(
      "cleaned up the grant: its secret is deleted and its login is gone"
    );
    expect(shown).toContain(
      '"from":"retired","to":"absent","owner":"analyst","databases":["orders","postgres"]'
    );
    expectNothingHiddenIn(shown);
  });

  it.each(["format", "ALTER ROLE", "REVOKE", "endSessions", "countSessions"])(
    "keeps the statement and its bindings out of the error and the log when PostgreSQL's error quotes those of %s in a cutoff",
    async (statement) => {
      given("active");
      db.memberships.push({ role: "analyst", member: LOGIN, byManager: true });
      db.failOn(statement, (sql, bindings) =>
        pgError("42501", `${sql} ${bindings.join(" ")} ${VERIFIER}`)
      );

      const shown = await shownBy(cutOff());

      expect(shown).toContain("connector request errored");
      expect(shown).toContain("42501");
      expectNothingHiddenIn(shown);
    }
  );

  it.each(["GRANT p0v_", "REASSIGN OWNED", "DROP OWNED", "DROP ROLE"])(
    "keeps the statement out of the error and the log when PostgreSQL's error quotes %s in a cleanup",
    async (statement) => {
      given("retired");
      db.failOn(statement, (sql) => pgError("42501", sql));

      const shown = await shownBy(cleanUp());

      expect(shown).toContain("connector request errored");
      expect(shown).toContain("42501");
      expectNothingHiddenIn(shown);
    }
  );

  it("keeps the secret manager's error out of the error and the log when it will not delete the grant secret", async () => {
    given("retired");
    vault.state.failNextDelete = new Error("DeleteSecret an earlier password", {
      cause: new Error("an earlier password"),
    });

    const shown = await shownBy(cleanUp());

    expect(shown).toContain("The connector could not delete the grant secret.");
    expectNothingHiddenIn(shown);
  });

  it("names nothing but the login, the count and the step when sessions outlive a cutoff", async () => {
    given("active");
    db.sessions.push({ usename: LOGIN, outlives: Infinity });

    const error = await errorOf(cutOff());
    const shown = `${inspect(error, { depth: 10 })}\n${log.lines.join("")}`;

    expect(connectorErrorOf(error).data.payload).toEqual({
      login: LOGIN,
      sessions: 1,
      step: "end_sessions",
    });
    expectNothingHiddenIn(shown);
  });

  /** What the call logged apart from the router's own lines, as its message
   * and the database the line names. */
  const logged = () =>
    log.lines
      .map((line) => z.parse(logLine, JSON.parse(line)))
      .filter(({ msg }) => !msg.startsWith("connector request"))
      .map(({ msg, database }) => [msg, database]);

  it("logs each durable point of a cutoff, with the roles it revoked, and no statement", async () => {
    given("active");
    db.memberships.push({ role: "analyst", member: LOGIN, byManager: true });

    const shown = await shownBy(cutOff());

    expect(logged()).toEqual([
      ["revoked the roles the manager granted the grant login", "postgres"],
      ["retired the grant login: it cannot log in", "postgres"],
      [
        "cut off the grant login and confirmed that none of its sessions is left",
        "postgres",
      ],
    ]);
    expect(shown).toContain('"revoked":["analyst"]');
    expectNothingHiddenIn(shown);
  });

  it("logs each durable point of a cleanup, each database released by its name, and no statement", async () => {
    given("retired");

    const shown = await shownBy(cleanUp());

    expect(logged()).toEqual([
      ["deleted the grant secret", "postgres"],
      [
        "released what the grant login owns and was granted in the database",
        "orders",
      ],
      [
        "released what the grant login owns and was granted in the database",
        "postgres",
      ],
      ["dropped the grant login", "postgres"],
      [
        "cleaned up the grant: its secret is deleted and its login is gone",
        "postgres",
      ],
    ]);
    expectNothingHiddenIn(shown);
  });

  it("logs no durable point that a failed step did not reach", async () => {
    given("retired");
    db.failOn("REASSIGN OWNED", pgError("57014"), "orders");

    await shownBy(cleanUp());

    expect(logged()).toEqual([["deleted the grant secret", "postgres"]]);
  });

  describe("the database a session's own lines name", () => {
    /** Each line holds the key once: a logger that binds `database` and
     * then a child that binds it again would write it twice. */
    const namesOnce = (message: string, database: string) => {
      const lines = log.lines.filter((line) => line.includes(message));
      expect(lines).toHaveLength(1);
      expect(lines[0]?.match(/"database":/g)).toHaveLength(1);
      expect(lines[0]).toContain(`"database":"${database}"`);
    };

    it("names the database of a connection that will not close", async () => {
      given("retired");
      db.failOn("close", pgError("57P01"), "orders");

      await expect(cleanUp()).resolves.toBe(null);

      namesOnce("failed to close the PostgreSQL connection", "orders");
    });

    it("names the database of a transaction that will not roll back", async () => {
      given("retired");
      db.failOn("REASSIGN OWNED", pgError("57014"), "orders");
      db.failOn("ROLLBACK", pgError("57P01"), "orders");

      await expect(dataOf(cleanUp())).resolves.toMatchObject({
        payload: { step: "release_owned", database: "orders" },
      });

      namesOnce("failed to roll back the PostgreSQL transaction", "orders");
    });

    it("names the target's database for a line about its own connection", async () => {
      given("retired");
      db.failOn("close", pgError("57P01"), "postgres");

      await expect(cleanUp()).resolves.toBe(null);

      expect(
        log.lines.filter((line) =>
          line.includes("failed to close the PostgreSQL connection")
        )
      ).toHaveLength(2);
      for (const line of log.lines.filter((l) =>
        l.includes("failed to close")
      )) {
        expect(line.match(/"database":/g)).toHaveLength(1);
        expect(line).toContain('"database":"postgres"');
      }
    });
  });
});

describe("a grant secret of another target", () => {
  it.each([
    [
      "the cutoff",
      () =>
        role().setPoliciesForUser({
          ...user,
          policies: [],
          context: { ...context, targetId: "billing-prod" },
        }),
    ],
    ["the cleanup", () => cleanUp({ targetId: "billing-prod" })],
  ])(
    "is refused by %s before Secrets Manager or PostgreSQL is called",
    async (_, call) => {
      given("active");
      const before = everything();

      await expect(dataOf(call())).resolves.toEqual({
        type: "validation_error",
        message:
          "The grant secret's name is for another target than the request's. Its target id must be the request's targetId.",
        payload: { host: context.target.host },
      });
      expect(journal).toEqual([]);
      expect(vault.reads).toEqual([]);
      expect(db.signIns).toEqual([]);
      expect(everything()).toEqual(before);
    }
  );
});

describe("the step and the database a failure names", () => {
  const calls = { cutoff: cutOff, cleanup: () => cleanUp() };

  it.each(["cutoff", "cleanup"] as const)(
    "the %s names read_login when the connector cannot read the manager secret",
    async (name) => {
      given("retired");
      vault.state.fail = new UnauthorizedError("aws");

      await expect(dataOf(calls[name]())).resolves.toMatchObject({
        type: "insufficient_privileges",
        payload: { step: "read_login" },
      });

      expect(db.calls).toEqual([]);
    }
  );

  it.each(["cutoff", "cleanup"] as const)(
    "the %s names read_login when PostgreSQL refuses the manager's sign-in",
    async (name) => {
      given("retired");
      db.failOn("login", pgError("28P01"));

      await expect(dataOf(calls[name]())).resolves.toMatchObject({
        type: "insufficient_privileges",
        payload: { sqlState: "28P01", step: "read_login" },
      });
    }
  );

  it("the cutoff names retire_login when PostgreSQL refuses the retirement for a reason other than a stall", async () => {
    given("active");
    db.failOn(RETIRE_STATEMENT, pgError("42501"));

    await expect(dataOf(cutOff())).resolves.toMatchObject({
      type: "insufficient_privileges",
      payload: { sqlState: "42501", step: "retire_login" },
    });
  });

  it("the cutoff names end_sessions when the sessions will not end between two attempts to retire the login", async () => {
    given("active");
    db.sessions.push({ usename: LOGIN });
    db.failOn(RETIRE_STATEMENT, pgError("55P03"));
    db.failOn("endSessions", pgError("57014"));

    await expect(dataOf(cutOff())).resolves.toMatchObject({
      payload: { sqlState: "57014", step: "end_sessions" },
    });
  });

  it("the cleanup names list_databases when PostgreSQL will not list them, and has handed nothing over", async () => {
    given("retired");
    db.objects.push(owned("orders", "orders.public.drafts"));
    db.failOn("connectableDatabases", pgError("57014"));

    await expect(dataOf(cleanUp())).resolves.toMatchObject({
      type: "upstream_unavailable",
      payload: { sqlState: "57014", step: "list_databases" },
    });

    expect(db.objects).toEqual([owned("orders", "orders.public.drafts")]);
  });

  it("the cleanup names end_sessions when the sessions will not end before an objectOwner that is not a grantable role is used, and has handed nothing over", async () => {
    given("retired");
    db.sessions.push({ usename: LOGIN, outlives: Infinity });

    await expect(
      dataOf(cleanUp({ objectOwner: "postgres" }))
    ).resolves.toMatchObject({
      type: "upstream_unavailable",
      payload: { login: LOGIN, sessions: 1, step: "end_sessions" },
    });

    expect(db.calls).not.toContain("connectableDatabases");
  });

  it("the cleanup names the second of three databases, not the target's own, after it has released the first", async () => {
    db = fakeDatabase(
      { databases: ["billing", "orders", "postgres"] },
      journal
    );
    given("retired");
    db.objects.push(
      owned("billing", "billing.public.ledger"),
      owned("orders", "orders.public.drafts")
    );
    db.failOn("REASSIGN OWNED", pgError("57014"), "orders");

    await expect(dataOf(cleanUp())).resolves.toEqual({
      type: "upstream_unavailable",
      message:
        "The connector could not reach PostgreSQL, or PostgreSQL did not answer in time. Check the network path from the connector to the target.",
      payload: { sqlState: "57014", step: "release_owned", database: "orders" },
    });

    expect(db.objects).toEqual([
      { ...owned("billing", "billing.public.ledger"), owner: "analyst" },
      owned("orders", "orders.public.drafts"),
    ]);
    expect(
      log.lines.filter((line) => line.includes("released what the grant"))
    ).toHaveLength(1);
    expect(log.lines.join("")).toContain('"database":"billing"');
  });

  it("leaves a failure that is not a ConnectorError as it is, with no step", async () => {
    given("active");
    db.sessions.push({ usename: LOGIN });
    const failure = new Error("the wait failed");
    wait = async () => {
      throw failure;
    };

    const error = await errorOf(cutOff());

    expect(error).not.toBeInstanceOf(ConnectorError);
    expect(error.cause).toBe(failure);
  });

  it("the cleanup names the database when the manager's sign-in to it is refused", async () => {
    given("retired");
    db.failOn("BEGIN", pgError("28P01"), "orders");

    await expect(dataOf(cleanUp())).resolves.toMatchObject({
      type: "insufficient_privileges",
      payload: { sqlState: "28P01", step: "release_owned", database: "orders" },
    });
  });
});
