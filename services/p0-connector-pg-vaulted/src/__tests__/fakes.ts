import { DescribeSecretCommand } from "@aws-sdk/client-secrets-manager";
import { ConnectorError, type Logger } from "@p0security/connector-core";
import {
  SecretAlreadyExistsError,
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretPayload,
  type SecretRef,
} from "@p0security/connector-secret-manager-client";
import { Writable } from "node:stream";
import { pino } from "pino";

import type { ConnectSecretManager, Dependencies } from "../dependencies.ts";
import {
  CAN_CREATE_ROLE_SQL,
  CAN_SIGNAL_BACKEND_SQL,
  CONNECTABLE_DATABASES_SQL,
  COUNT_SESSIONS_SQL,
  END_SESSIONS_SQL,
  GRANTABLE_ROLES_SQL,
  HAS_GRANT_OPTIONS_SQL,
  IS_GRANTABLE_ROLE_SQL,
  LOGIN_SQL,
  MANAGER_GRANTED_ROLES_SQL,
  OWNS_ANYTHING_SQL,
  OWNS_HERE_SQL,
  PING_SQL,
  SET_LOCK_TIMEOUT_SQL,
} from "../postgres/catalog.ts";
import type {
  Connect,
  ManagerSignIn,
  PgDriver,
  PgQuery,
} from "../postgres/client.ts";
import { target } from "./fixtures.ts";

/** The fixture target's manager secret. */
export const MANAGER_SECRET_ARN = target.managerSecretArn;

export const MANAGER = {
  username: "p0_manager",
  password: "correct-horse-battery-staple",
};

// copy of `errorOf`, `connectorErrorOf` and `dataOf` in services/p0-connector-aws-ssm-ai/src/__tests__/fakes.ts
/** The error a call rejected with. */
export const errorOf = async (promise: Promise<unknown>) => {
  const error = await promise.catch((e: unknown) => e);
  if (!(error instanceof Error)) {
    throw new Error(`expected an Error, got ${String(error)}`);
  }
  return error;
};

/** The connector error a call threw, which tRPC can wrap. */
export const connectorErrorOf = (error: Error) => {
  if (error instanceof ConnectorError) return error;
  if (error.cause instanceof ConnectorError) return error.cause;
  throw new Error(`expected a ConnectorError, got ${String(error)}`);
};

/** The data of the connector error a call rejected with. */
export const dataOf = async (promise: Promise<unknown>) =>
  connectorErrorOf(await errorOf(promise)).data;

// copy of `capturingLogger` in services/p0-connector-snowflake-ai/src/__tests__/fakes.ts
/** A pino logger that keeps every line it writes, at every level. */
export const capturingLogger = () => {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer, _encoding, done) {
      lines.push(chunk.toString());
      done();
    },
  });
  const logger: Logger = pino({ level: "trace" }, stream);
  return { logger, lines };
};

/**
 * Every call the fakes got, in order, when they share one journal: a secret
 * call as `<operation> <secret>`, a database call as the database's own
 * `calls` have it, and a wait as `wait <milliseconds>`.
 */
export type Journal = (string[] | string)[];

/** A wait that returns at once, and is kept in the journal. */
export const fakeWait = (journal: Journal) => async (ms: number) => {
  journal.push(`wait ${ms}`);
};

/**
 * Randomness that repeats: the nth draw is bytes of value n. The passwords
 * and verifiers it leads to are `FIRST_PASSWORD` and `SECOND_PASSWORD` in ./fixtures.ts.
 */
export const fakeRandomBytes = () => {
  let draws = 0;
  return (size: number) => Buffer.alloc(size, ++draws);
};

// copy of `Command` and `sdkError` in services/p0-connector-aws-ssm-ai/src/__tests__/fakes.ts
/** An SDK command as a fake AWS client gets it: its class and its input. */
type Command = {
  constructor: { name: string };
  input: Record<string, unknown>;
};

/** An SDK failure, which the SDK names by `name`. */
export const sdkError = (name: string, message = name) =>
  Object.assign(new Error(message), { name });

type FakeGrantSecret = {
  values: Buffer[];
  /** Set while AWS deletes the secret in the background. */
  deletedDate?: Date;
  /** No version has a staging label, so the secret serves no value. */
  unstaged?: boolean;
};

type FakeSecretStoreState = {
  /** Every read throws this. */
  fail?: Error;
  /** Every describe throws this. */
  failDescribe?: Error;
  /** The next create throws this. */
  failNextCreate?: Error;
  /** The next write throws what this returns, given the value to write. */
  failNextWrite?: (value: Buffer) => Error;
  /** The next delete throws this. */
  failNextDelete?: Error;
};

// The shared client's refs are a brand on a string, which only a cast makes.
const refOf = (ref: string) => ref as SecretRef;

// modelled on `fakeSecretsManager` in services/p0-connector-aws-ssm-ai/src/__tests__/fakes.ts
/**
 * Secrets Manager in memory: the shared client the connector reads a manager
 * secret with and creates, writes and deletes a grant secret with, and the
 * SDK client it describes a grant secret with.
 *
 * The readable values are by ARN, and hold the fixture manager's secret
 * unless given others. A grant secret is by name, in `secrets`, and is
 * created with no value, as the real client creates it. Every read is kept,
 * of whatever secret.
 */
export const fakeSecretStore = (
  values: Record<string, SecretPayload> = {
    [MANAGER_SECRET_ARN]: JSON.stringify(MANAGER),
  },
  journal: Journal = []
) => {
  const reads: { config: SecretManagerProviderConfig; ref: string }[] = [];
  /** Grant secret name to secret. */
  const secrets = new Map<string, FakeGrantSecret>();
  /** The region of every call but a read, in order. */
  const regions: string[] = [];
  const state: FakeSecretStoreState = {};

  const connectSecretManager: ConnectSecretManager = async (config) => {
    const called = (operation: string, secret: string) => {
      journal.push(`${operation} ${secret}`);
      if (operation !== "getSecretValue" && config.provider === "aws") {
        regions.push(config.region);
      }
    };
    return {
      getSecretValue: async ({ ref }) => {
        called("getSecretValue", ref);
        reads.push({ config, ref });
        if (state.fail) throw state.fail;
        const value = values[ref] ?? secrets.get(ref)?.values.at(-1);
        if (value === undefined) throw new SecretNotFoundError(ref);
        return { value };
      },
      createSecret: async ({ name }) => {
        called("createSecret", name);
        const { failNextCreate } = state;
        if (failNextCreate) {
          state.failNextCreate = undefined;
          throw failNextCreate;
        }
        const existing = secrets.get(name);
        if (existing?.deletedDate) {
          throw sdkError(
            "InvalidRequestException",
            "You can't create this secret because a secret with this name is already scheduled for deletion."
          );
        }
        if (existing) throw new SecretAlreadyExistsError(name);
        secrets.set(name, { values: [] });
      },
      createSecretVersion: async ({ ref, value }) => {
        called("createSecretVersion", ref);
        const secret = secrets.get(ref);
        if (!secret) throw new SecretNotFoundError(refOf(ref));
        const { failNextWrite } = state;
        if (failNextWrite) {
          state.failNextWrite = undefined;
          throw failNextWrite(value);
        }
        secret.values.push(value);
      },
      deleteSecret: async ({ ref }) => {
        called("deleteSecret", ref);
        const { failNextDelete } = state;
        if (failNextDelete) {
          state.failNextDelete = undefined;
          throw failNextDelete;
        }
        if (!secrets.delete(ref)) throw new SecretNotFoundError(ref);
      },
    };
  };

  const secretsManagerSdk: Dependencies["secretsManagerSdk"] = (region) => ({
    send: async (command: Command) => {
      if (!(command instanceof DescribeSecretCommand)) {
        throw new Error(`the store doesn't send ${command.constructor.name}`);
      }
      const name = command.input.SecretId ?? "";
      journal.push(`describeSecret ${name}`);
      regions.push(region);
      if (state.failDescribe) throw state.failDescribe;
      const secret = secrets.get(name);
      if (!secret) {
        throw sdkError(
          "ResourceNotFoundException",
          "Secrets Manager can't find the specified secret."
        );
      }
      const { values: written, deletedDate, unstaged } = secret;
      return {
        Name: name,
        DeletedDate: deletedDate,
        VersionIdsToStages:
          written.length > 0
            ? { [`v${written.length}`]: unstaged ? [] : ["AWSCURRENT"] }
            : {},
      };
    },
  });

  return {
    connectSecretManager,
    secretsManagerSdk,
    reads,
    secrets,
    regions,
    state,
    /** The current value of the named grant secret, as text. */
    valueOf: (name: string) => secrets.get(name)?.values.at(-1)?.toString(),
    /** Leaves a grant secret as an earlier call did: with `value`, or
     * created and never written. */
    holding: (name: string, value?: string) => {
      secrets.set(name, {
        values: value === undefined ? [] : [Buffer.from(value)],
      });
    },
  };
};

/** An error as the driver throws it for a server's answer. Its message
 * quotes the statement, as the server's can. */
export const pgError = (sqlState: string, statement = "select 1") =>
  Object.assign(new Error(`${statement} - the server's own message`), {
    code: sqlState,
    severity: "ERROR",
  });

/** An error as the driver throws it when the network fails. */
export const networkError = (code: string) =>
  Object.assign(new Error(`connect ${code} 10.0.0.7:5432`), { code });

/** A role as the fake target keeps it. */
export type FakeRole = {
  canLogin: boolean;
  connectionLimit: number;
  /** What `PASSWORD` was given, which is a verifier. */
  password?: string;
  validUntil?: string;
  comment?: string;
};

/** One role's membership in another, and whether the manager granted it:
 * the manager is, or holds the privileges of, the grantor. The grantor is
 * the manager unless it says otherwise, and PostgreSQL 16 and later keep it. */
export type FakeMembership = {
  role: string;
  member: string;
  byManager: boolean;
  grantor?: string;
};

/** Something in one database that depends on roles: its owner, and the
 * roles that were granted a privilege on it. */
export type FakeObject = {
  database: string;
  name: string;
  owner: string;
  grantees: string[];
};

/** An open session of a login. Once it is signalled to end, `outlives` more
 * counts still see it: none unless given, and all of them for `Infinity`. */
export type FakeSession = {
  usename: string;
  outlives?: number;
  signalled?: boolean;
};

/** What the manager can do, and what the target holds. */
type FakeTarget = {
  canCreateRole: boolean;
  canSignalBackend: boolean;
  /** PostgreSQL 16 or later. */
  hasGrantOptions: boolean;
  /** A `REVOKE` prints a warning and removes nothing, as PostgreSQL 16's
   * does when it infers another grantor than the recorded one. */
  ignoresRevoke: boolean;
  grantableRoles: string[];
  databases: string[];
  /** The databases the manager cannot connect to. */
  closedDatabases: string[];
};

/** What a statement changes, which a rolled-back transaction puts back. */
type FakeCatalog = {
  roles: Map<string, FakeRole>;
  memberships: FakeMembership[];
  objects: FakeObject[];
};

/** Where a statement runs: the database of its connection, and the
 * target. */
type FakeConnection = { database: string; is: FakeTarget };

/** The error a failing statement throws, or what makes it from the
 * statement and its bindings, which a driver's error can quote. */
type Failure = Error | ((sql: string, bindings: readonly string[]) => Error);

// As `quote_ident` and `quote_literal` write them. `quote_ident` also
// quotes a keyword, which no name in the tests is.
const quoteIdent = (name: string) =>
  /^[a-z_][a-z0-9_]*$/.test(name) ? name : `"${name.replaceAll('"', '""')}"`;
const quoteLiteral = (text: string) => {
  const quoted = `'${text.replaceAll("'", "''")}'`;
  return text.includes("\\") ? `E${quoted.replaceAll("\\", "\\\\")}` : quoted;
};

/** PostgreSQL's `format()`, for `%I` and `%L`. */
const format = (template: string, args: readonly string[]) => {
  let next = 0;
  return template.replace(/%[IL]/g, (spec) => {
    const arg = args[next++] ?? "";
    return spec === "%I" ? quoteIdent(arg) : quoteLiteral(arg);
  });
};

const nameOf = (quoted = "") =>
  quoted.startsWith('"') ? quoted.slice(1, -1).replaceAll('""', '"') : quoted;
const textOf = (literal = "") =>
  literal.startsWith("E")
    ? literal.slice(2, -1).replaceAll("''", "'").replaceAll("\\\\", "\\")
    : literal.slice(1, -1).replaceAll("''", "'");

const NAME = `("(?:[^"]|"")+"|[a-z_][a-z0-9_]*)`;
const LITERAL = `(E?'(?:[^']|'')*')`;
const FORMAT_SQL =
  /^SELECT format\(\$\d+::text(?:, \$\d+::text)*\) AS statement$/;

/** The named role, or the error PostgreSQL answers with when there is
 * none. */
const existing = ({ roles }: FakeCatalog, quoted?: string) => {
  const role = roles.get(nameOf(quoted));
  if (!role) throw pgError("42704");
  return role;
};

/** Throws as PostgreSQL does unless the manager holds the privileges of the
 * role named `quoted`, which it does once it has granted itself the role. */
const requirePrivilegesOf = (catalog: FakeCatalog, quoted?: string) => {
  existing(catalog, quoted);
  const isMember = catalog.memberships.some(
    ({ role, member }) => role === nameOf(quoted) && member === MANAGER.username
  );
  if (!isMember) throw pgError("42501");
};

/** Each statement the connector runs: its shape, and what it does to the
 * catalog, given the names and literals the shape captured, as written, and
 * the connection it runs on. */
const STATEMENTS: {
  shape: RegExp;
  run: (
    catalog: FakeCatalog,
    captured: (string | undefined)[],
    connection: FakeConnection
  ) => void;
}[] = [
  {
    shape: new RegExp(
      `^CREATE ROLE ${NAME} NOLOGIN(?: PASSWORD ${LITERAL} VALID UNTIL ${LITERAL})?$`
    ),
    run: ({ roles }, [name, password, validUntil]) => {
      if (roles.has(nameOf(name))) throw pgError("42710");
      roles.set(nameOf(name), {
        canLogin: false,
        connectionLimit: -1,
        ...(password === undefined
          ? {}
          : { password: textOf(password), validUntil: textOf(validUntil) }),
      });
    },
  },
  {
    shape: new RegExp(
      `^ALTER ROLE ${NAME} PASSWORD ${LITERAL} VALID UNTIL ${LITERAL}$`
    ),
    run: (catalog, [name, password, validUntil]) => {
      Object.assign(existing(catalog, name), {
        password: textOf(password),
        validUntil: textOf(validUntil),
      });
    },
  },
  {
    shape: new RegExp(`^ALTER ROLE ${NAME} LOGIN VALID UNTIL ${LITERAL}$`),
    run: (catalog, [name, validUntil]) => {
      Object.assign(existing(catalog, name), {
        canLogin: true,
        validUntil: textOf(validUntil),
      });
    },
  },
  {
    shape: new RegExp(`^COMMENT ON ROLE ${NAME} IS ${LITERAL}$`),
    run: (catalog, [name, comment]) => {
      existing(catalog, name).comment = textOf(comment);
    },
  },
  {
    shape: new RegExp(
      `^ALTER ROLE ${NAME} NOLOGIN CONNECTION LIMIT 0 PASSWORD NULL$`
    ),
    run: (catalog, [name]) => {
      const role = existing(catalog, name);
      role.canLogin = false;
      role.connectionLimit = 0;
      delete role.password;
    },
  },
  // The manager's grant of a role to itself, which only PostgreSQL 16 and
  // later take `WITH INHERIT` on.
  {
    shape: new RegExp(`^GRANT ${NAME} TO current_user( WITH INHERIT TRUE)?$`),
    run: (catalog, [quotedRole, option], { is }) => {
      if ((option !== undefined) !== is.hasGrantOptions) throw pgError("42601");
      existing(catalog, quotedRole);
      const membership = {
        role: nameOf(quotedRole),
        member: MANAGER.username,
        byManager: true,
      };
      const { memberships } = catalog;
      if (
        !memberships.some(
          (m) => m.role === membership.role && m.member === membership.member
        )
      ) {
        memberships.push(membership);
      }
    },
  },
  {
    shape: new RegExp(`^REASSIGN OWNED BY ${NAME} TO ${NAME}$`),
    run: (catalog, [quotedFrom, quotedTo], { database, is }) => {
      requirePrivilegesOf(catalog, quotedFrom);
      const [from, to] = [nameOf(quotedFrom), nameOf(quotedTo)];
      if (!is.grantableRoles.includes(to)) throw pgError("42501");
      for (const object of catalog.objects) {
        if (object.database === database && object.owner === from) {
          object.owner = to;
        }
      }
    },
  },
  {
    shape: new RegExp(`^DROP OWNED BY ${NAME}$`),
    run: (catalog, [quoted], { database }) => {
      requirePrivilegesOf(catalog, quoted);
      const role = nameOf(quoted);
      const kept = catalog.objects.filter(
        (object) => object.database !== database || object.owner !== role
      );
      for (const object of kept) {
        if (object.database === database) {
          object.grantees = object.grantees.filter((name) => name !== role);
        }
      }
      catalog.objects.splice(0, Infinity, ...kept);
    },
  },
  {
    shape: new RegExp(`^DROP ROLE ${NAME}$`),
    run: (catalog, [quoted]) => {
      existing(catalog, quoted);
      const role = nameOf(quoted);
      const isDependedOn = catalog.objects.some(
        ({ owner, grantees }) => owner === role || grantees.includes(role)
      );
      if (isDependedOn) throw pgError("2BP01");
      catalog.roles.delete(role);
      catalog.memberships.splice(
        0,
        Infinity,
        ...catalog.memberships.filter(
          (m) => m.role !== role && m.member !== role
        )
      );
    },
  },
  {
    shape: new RegExp(`^GRANT ${NAME} TO ${NAME}$`),
    run: (catalog, [quotedRole, quotedMember]) => {
      existing(catalog, quotedMember);
      const [role, member] = [nameOf(quotedRole), nameOf(quotedMember)];
      const { memberships } = catalog;
      if (!memberships.some((m) => m.role === role && m.member === member)) {
        memberships.push({
          role,
          member,
          byManager: true,
          grantor: MANAGER.username,
        });
      }
    },
  },
  {
    shape: new RegExp(`^REVOKE ${NAME} FROM ${NAME}(?: GRANTED BY ${NAME})?$`),
    run: (catalog, [quotedRole, quotedMember, quotedGrantor], { is }) => {
      existing(catalog, quotedMember);
      const [role, member] = [nameOf(quotedRole), nameOf(quotedMember)];
      const { memberships } = catalog;
      // PostgreSQL 16 removes the membership of the grantor it names, or
      // else of the one it infers, which here is the manager. Before 16 the
      // membership is removed whoever granted it.
      const grantor = quotedGrantor
        ? nameOf(quotedGrantor)
        : is.hasGrantOptions
          ? MANAGER.username
          : undefined;
      const at = memberships.findIndex(
        (m) =>
          m.role === role &&
          m.member === member &&
          m.byManager &&
          (grantor === undefined || (m.grantor ?? MANAGER.username) === grantor)
      );
      if (at >= 0 && !is.ignoresRevoke) memberships.splice(at, 1);
    },
  },
];

/**
 * A PostgreSQL target behind the driver. It answers the connector's catalog
 * statements from `is`, `roles`, `memberships` and `sessions`, builds a
 * statement as `format()` does, runs each statement the connector is known
 * to run, and refuses any other as a syntax error. A rolled-back transaction
 * leaves `roles`, `memberships` and `objects` as they were when it began.
 *
 * Each connection is to one database, which is where `REASSIGN OWNED` and
 * `DROP OWNED` act. The manager's own memberships are kept under
 * `MANAGER.username`.
 */
export const fakeDatabase = (
  overrides: Partial<FakeTarget> = {},
  journal: Journal = []
) => {
  const is: FakeTarget = {
    canCreateRole: true,
    canSignalBackend: true,
    hasGrantOptions: true,
    ignoresRevoke: false,
    grantableRoles: ["analyst", "reporting"],
    databases: ["orders", "postgres"],
    closedDatabases: [],
    ...overrides,
  };
  const catalog: FakeCatalog = {
    roles: new Map(),
    memberships: [],
    objects: [],
  };
  const sessions: FakeSession[] = [];
  const pids = new WeakMap<FakeSession, number>();
  let lastPid = 1000;
  /** The backend of a session, which no other session has. */
  const pidOf = (session: FakeSession) => {
    const pid = pids.get(session) ?? ++lastPid;
    pids.set(session, pid);
    return pid;
  };
  const named = (names: string[]) => names.map((name) => ({ name }));
  const answers: Record<
    string,
    {
      call: string;
      rows: (bindings: readonly string[], database: string) => unknown[];
    }
  > = {
    [PING_SQL]: { call: "ping", rows: () => [{ "?column?": 1 }] },
    [CAN_CREATE_ROLE_SQL]: {
      call: "canCreateRole",
      rows: () => [{ allowed: is.canCreateRole }],
    },
    [CAN_SIGNAL_BACKEND_SQL]: {
      call: "canSignalBackend",
      rows: () => [{ allowed: is.canSignalBackend }],
    },
    [HAS_GRANT_OPTIONS_SQL]: {
      call: "hasGrantOptions",
      rows: () => [{ allowed: is.hasGrantOptions }],
    },
    [GRANTABLE_ROLES_SQL]: {
      call: "grantableRoles",
      rows: () => named(is.grantableRoles),
    },
    [CONNECTABLE_DATABASES_SQL]: {
      call: "connectableDatabases",
      rows: () =>
        named(is.databases.filter((d) => !is.closedDatabases.includes(d))),
    },
    [SET_LOCK_TIMEOUT_SQL]: {
      call: "setLockTimeout",
      rows: ([timeout]) => [{ set_config: timeout }],
    },
    [END_SESSIONS_SQL]: {
      call: "endSessions",
      rows: ([login]) => {
        const signalled = sessions.filter(({ usename }) => usename === login);
        for (const session of signalled) session.signalled = true;
        return signalled.map((session) => ({
          pid: pidOf(session),
          ended: true,
        }));
      },
    },
    [COUNT_SESSIONS_SQL]: {
      call: "countSessions",
      rows: ([login]) => {
        const seen = sessions.filter(({ usename }) => usename === login);
        for (const session of seen) {
          if (!session.signalled) continue;
          const outlives = session.outlives ?? 0;
          if (outlives > 0) session.outlives = outlives - 1;
          else sessions.splice(sessions.indexOf(session), 1);
        }
        return [
          {
            sessions: sessions.filter(({ usename }) => usename === login)
              .length,
          },
        ];
      },
    },
    [OWNS_ANYTHING_SQL]: {
      call: "ownsAnything",
      rows: ([login]) => [
        { allowed: catalog.objects.some(({ owner }) => owner === login) },
      ],
    },
    [OWNS_HERE_SQL]: {
      call: "ownsHere",
      rows: ([login], database) => [
        {
          allowed: catalog.objects.some(
            (object) => object.owner === login && object.database === database
          ),
        },
      ],
    },
    [IS_GRANTABLE_ROLE_SQL]: {
      call: "isGrantableRole",
      rows: ([role = ""]) => [{ allowed: is.grantableRoles.includes(role) }],
    },
    [LOGIN_SQL]: {
      call: "login",
      rows: ([login = ""]) => {
        const role = catalog.roles.get(login);
        return role
          ? [{ canLogin: role.canLogin, connectionLimit: role.connectionLimit }]
          : [];
      },
    },
    [MANAGER_GRANTED_ROLES_SQL]: {
      call: "managerGrantedRoles",
      rows: ([login]) =>
        catalog.memberships
          .filter(({ member, byManager }) => member === login && byManager)
          .map(({ role, grantor = MANAGER.username }) => ({
            name: role,
            grantor: is.hasGrantOptions ? grantor : null,
          }))
          // As `COLLATE "C"` sorts.
          .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)),
    },
  };

  const signIns: ManagerSignIn[] = [];
  /** Every statement in order: a catalog statement by its name, followed by
   * its bindings when it has any, `format` and its bindings for a statement
   * the target builds, any other as its text, and `close` when the driver
   * closes. */
  const calls: Journal = [];
  const failures: { prefix: string; failure: Failure; database?: string }[] =
    [];

  const record = (call: string[] | string) => {
    calls.push(call);
    journal.push(call);
  };

  const run = (sql: string, database: string) => {
    for (const { shape, run: change } of STATEMENTS) {
      const [matched, ...captured] = shape.exec(sql) ?? [];
      if (matched === undefined) continue;
      change(catalog, captured, { database, is });
      return [];
    }
    throw pgError("42601", sql);
  };

  /** A connection to `database`, which refuses the manager when the
   * database is closed to it. */
  const driverTo = (database: string): PgDriver => {
    /** Throws when the call is one that is set to fail. */
    const failing = (
      name: string,
      sql: string,
      bindings: readonly string[]
    ) => {
      const failed = failures.find(
        (failure) =>
          name.startsWith(failure.prefix) &&
          (failure.database ?? database) === database
      );
      if (!failed) return;
      const { failure } = failed;
      throw typeof failure === "function" ? failure(sql, bindings) : failure;
    };

    /** Records a call, and throws when it is one that is set to fail. */
    const called = (name: string, sql: string, bindings: readonly string[]) => {
      record(bindings.length > 0 ? [name, ...bindings] : name);
      if (is.closedDatabases.includes(database)) throw pgError("42501");
      failing(name, sql, bindings);
    };

    const query: PgQuery = async (sql, bindings = []) => {
      const answer = answers[sql];
      const name = answer?.call ?? (FORMAT_SQL.test(sql) ? "format" : sql);
      called(name, sql, bindings);
      if (answer) return answer.rows(bindings, database);
      if (name === "format") {
        const [template = "", ...args] = bindings;
        return [{ statement: format(template, args) }];
      }
      return run(sql, database);
    };

    return {
      query,
      begin: async () => {
        called("BEGIN", "BEGIN", []);
        const before = structuredClone(catalog);
        return {
          query,
          commit: async () => {
            called("COMMIT", "COMMIT", []);
          },
          rollback: async () => {
            called("ROLLBACK", "ROLLBACK", []);
            catalog.roles.clear();
            for (const [name, role] of before.roles) {
              catalog.roles.set(name, role);
            }
            catalog.memberships.splice(0, Infinity, ...before.memberships);
            catalog.objects.splice(0, Infinity, ...before.objects);
          },
        };
      },
      close: async () => {
        record("close");
        failing("close", "close", []);
      },
    };
  };

  const connect: Connect = (signIn) => {
    signIns.push(signIn);
    return driverTo(signIn.database);
  };

  return {
    connect,
    is,
    signIns,
    calls,
    /** The roles that statements created or changed and no rollback undid,
     * by name. A test sets one to start from a state. */
    roles: catalog.roles,
    memberships: catalog.memberships,
    /** What depends on roles, in each database. */
    objects: catalog.objects,
    /** The open sessions of logins. */
    sessions,
    /** The statement whose call starts with `prefix`, or `close`, throws `failure`, on
     * every connection or on those to `database`, until the function this
     * returns is called. */
    failOn: (prefix: string, failure: Failure, database?: string) => {
      const entry = { prefix, failure, database };
      failures.push(entry);
      return () => {
        failures.splice(failures.indexOf(entry), 1);
      };
    },
  };
};

/** `calls` with the probe role's random name replaced, so a test can state
 * them. Only a name that is a grant login's is replaced. */
export const withoutProbeName = (calls: Journal) => {
  const named = (text: string) => text.replace(/p0v_[0-9a-f]{32}/g, "<probe>");
  return calls.map((call) =>
    typeof call === "string" ? named(call) : call.map(named)
  );
};
