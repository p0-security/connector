import { ConnectorError, type Logger } from "@p0security/connector-core";
import {
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretPayload,
} from "@p0security/connector-secret-manager-client";
import { Writable } from "node:stream";
import { pino } from "pino";

import type { ConnectSecretManager } from "../manager.ts";
import {
  CAN_CREATE_ROLE_SQL,
  CAN_SIGNAL_BACKEND_SQL,
  DATABASES_SQL,
  GRANTABLE_ROLES_SQL,
  HAS_GRANT_OPTIONS_SQL,
  PING_SQL,
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
 * Secrets Manager in memory, by ARN. It holds the fixture manager's secret
 * unless given other values, and keeps every read's region and ARN.
 */
export const fakeSecretStore = (
  values: Record<string, SecretPayload> = {
    [MANAGER_SECRET_ARN]: JSON.stringify(MANAGER),
  }
) => {
  const reads: { config: SecretManagerProviderConfig; ref: string }[] = [];
  /** Every read throws `fail`. */
  const state: { fail?: Error } = {};
  const connectSecretManager: ConnectSecretManager = async (config) => ({
    getSecretValue: async ({ ref }) => {
      reads.push({ config, ref });
      if (state.fail) throw state.fail;
      const value = values[ref];
      if (value === undefined) throw new SecretNotFoundError(ref);
      return { value };
    },
  });
  return { connectSecretManager, reads, state };
};

/** An error as the driver throws it for a server's answer. Its message
 * quotes the statement, as knex's does. */
export const pgError = (sqlState: string, statement = "select 1") =>
  Object.assign(new Error(`${statement} - the server's own message`), {
    code: sqlState,
    severity: "ERROR",
  });

/** An error as the driver throws it when the network fails. */
export const networkError = (code: string) =>
  Object.assign(new Error(`connect ${code} 10.0.0.7:5432`), { code });

/** What the manager can do, and what the target holds. */
type FakeTarget = {
  canCreateRole: boolean;
  canSignalBackend: boolean;
  /** PostgreSQL 16 or later. */
  hasGrantOptions: boolean;
  grantableRoles: string[];
  databases: string[];
};

/**
 * A PostgreSQL target behind the driver. It answers the connector's catalog
 * statements from `is`, keeps the roles a statement creates, and forgets
 * those a rolled-back transaction created.
 */
export const fakeDatabase = (overrides: Partial<FakeTarget> = {}) => {
  const is: FakeTarget = {
    canCreateRole: true,
    canSignalBackend: true,
    hasGrantOptions: true,
    grantableRoles: ["analyst", "reporting"],
    databases: ["orders", "postgres"],
    ...overrides,
  };
  const named = (names: string[]) => names.map((name) => ({ name }));
  const catalog: Record<string, { call: string; rows: () => unknown[] }> = {
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
    [DATABASES_SQL]: { call: "databases", rows: () => named(is.databases) },
  };

  const signIns: ManagerSignIn[] = [];
  /** Every statement in order: a catalog statement by its name, any other
   * as its text, and `close` when the driver closes. */
  const calls: string[] = [];
  /** The roles that statements created and no rollback undid. */
  const roles = new Set<string>();
  const failures: { prefix: string; error: unknown }[] = [];

  const queryInto =
    (created: string[]): PgQuery =>
    async (sql) => {
      const answer = catalog[sql];
      const call = answer?.call ?? sql;
      calls.push(call);
      const failure = failures.find(({ prefix }) => call.startsWith(prefix));
      if (failure) throw failure.error;
      if (answer) return answer.rows();
      const [, role] = /^CREATE ROLE "([^"]+)"/.exec(sql) ?? [];
      if (role) {
        roles.add(role);
        created.push(role);
      }
      return [];
    };

  const driver: PgDriver = {
    query: queryInto([]),
    begin: async () => {
      calls.push("BEGIN");
      const created: string[] = [];
      return {
        query: queryInto(created),
        rollback: async () => {
          calls.push("ROLLBACK");
          for (const role of created) roles.delete(role);
        },
      };
    },
    close: async () => {
      calls.push("close");
    },
  };

  const connect: Connect = (signIn) => {
    signIns.push(signIn);
    return driver;
  };

  return {
    connect,
    is,
    signIns,
    calls,
    roles,
    /** The statement whose call starts with `prefix` throws `error`. */
    failOn: (prefix: string, error: unknown) => {
      failures.push({ prefix, error });
    },
  };
};

/** `calls` with the probe role's random name replaced, so a test can state
 * them. Only a name that is a grant login's is replaced. */
export const withoutProbeName = (calls: string[]) =>
  calls.map((call) => call.replace(/p0v_[0-9a-f]{32}/g, "<probe>"));
