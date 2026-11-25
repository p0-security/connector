import { ConnectorError, type Logger } from "@p0security/connector-core";
import {
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretPayload,
} from "@p0security/connector-secret-manager-client";
import type { Knex } from "knex";
import { Writable } from "node:stream";
import { pino } from "pino";

import type { ConnectSecretManager } from "../manager.ts";
import {
  CAN_CREATE_ROLE_SQL,
  CAN_SIGNAL_BACKEND_SQL,
  GRANTABLE_ROLES_SQL,
  HAS_GRANT_OPTIONS_SQL,
  PING_SQL,
} from "../postgres/catalog.ts";
import { target } from "./fixtures.ts";

/** The fixture target's manager secret, a secret P0 names. */
export const MANAGER_SECRET = target.managerSecret;

/** The connector's environment in Lambda, which reads a manager secret P0
 * names in its `AWS_REGION`. */
export const CONNECTOR_ENV = { AWS_REGION: "us-east-1" };

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
 * Secrets Manager in memory, by name or ARN. It holds the fixture manager's
 * secret unless given other values, and keeps every read's region and
 * secret.
 */
export const fakeSecretStore = (
  values: Record<string, SecretPayload> = {
    [MANAGER_SECRET]: JSON.stringify(MANAGER),
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
};

/**
 * A PostgreSQL target behind knex. It answers the connector's catalog
 * statements from `is`, keeps the roles a statement creates, and forgets
 * those a rolled-back transaction created.
 */
export const fakeDatabase = (overrides: Partial<FakeTarget> = {}) => {
  const is: FakeTarget = {
    canCreateRole: true,
    canSignalBackend: true,
    hasGrantOptions: true,
    grantableRoles: ["analyst", "reporting"],
    ...overrides,
  };
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
      rows: () => is.grantableRoles.map((name) => ({ name })),
    },
  };

  /** Who each client knex built signs in as, and where. */
  const signIns: Pick<
    Knex.PgConnectionConfig,
    "database" | "host" | "password" | "port" | "user"
  >[] = [];
  /** Every statement in order: a catalog statement by its name, any other
   * as its text, and `close` when the client is destroyed. */
  const calls: string[] = [];
  /** The roles that statements created and no rollback undid. */
  const roles = new Set<string>();
  const failures: { prefix: string; error: unknown }[] = [];

  const runnerInto = (created: string[]) => ({
    raw: async (sql: string) => {
      const answer = catalog[sql];
      const call = answer?.call ?? sql;
      calls.push(call);
      const failure = failures.find(({ prefix }) => call.startsWith(prefix));
      if (failure) throw failure.error;
      if (answer) return { rows: answer.rows() };
      const [, role] = /^CREATE ROLE "([^"]+)"/.exec(sql) ?? [];
      if (role) {
        roles.add(role);
        created.push(role);
      }
      return { rows: [] };
    },
  });

  const client = {
    ...runnerInto([]),
    transaction: async () => {
      calls.push("BEGIN");
      const created: string[] = [];
      return {
        ...runnerInto(created),
        rollback: async () => {
          calls.push("ROLLBACK");
          for (const role of created) roles.delete(role);
        },
      };
    },
    destroy: async () => {
      calls.push("close");
    },
  };

  const knex = (config: Knex.Config) => {
    const { host, port, database, user, password } =
      config.connection as Knex.PgConnectionConfig;
    signIns.push({ host, port, database, user, password });
    // Only the calls the connector makes: the rest of knex is absent.
    return client as unknown as Knex;
  };

  return {
    knex,
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
