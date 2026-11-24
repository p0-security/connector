import type { Logger } from "@p0security/connector-core";
import awsCaBundle from "aws-ssl-profiles";
import knex, { type Knex } from "knex";

import type { Target } from "../context.ts";
import { toConnectorError } from "./errors.ts";

/** Runs one statement and returns its rows. */
export type PgQuery = (sql: string) => Promise<unknown[]>;

/**
 * The driver calls the connector makes, which is what stands in for
 * PostgreSQL in tests. A failure is whatever the driver throws.
 */
export type PgDriver = {
  query: PgQuery;
  /** Opens a transaction that holds one connection until it is rolled back. */
  begin: () => Promise<{ query: PgQuery; rollback: () => Promise<void> }>;
  close: () => Promise<void>;
};

/** A target's address and database, and the manager's credential for it. */
export type ManagerSignIn = Pick<Target, "database" | "host" | "port"> & {
  username: string;
  password: string;
};

/** Opens the driver. It connects on its first statement. */
export type Connect = (signIn: ManagerSignIn) => PgDriver;

const CONNECTION_TIMEOUT_MS = 10_000;
const STATEMENT_TIMEOUT_MS = 15_000;

// knex writes the driver's errors to the console, and a driver's error
// quotes its statement. The connector logs the mapped failure instead.
const SILENT = {
  warn: () => {},
  error: () => {},
  debug: () => {},
  deprecate: () => {},
};

/**
 * A driver that connects with `ssl`, as one client per request. Only the
 * integration tests pass anything but {@link connect}'s TLS, to reach a
 * local database. No request can.
 */
export const connectWith =
  (ssl: Knex.PgConnectionConfig["ssl"]): Connect =>
  ({ host, port, database, username, password }) => {
    const client = knex({
      client: "pg",
      connection: {
        host,
        port,
        database,
        user: username,
        password,
        ssl,
        connectionTimeoutMillis: CONNECTION_TIMEOUT_MS,
        statement_timeout: STATEMENT_TIMEOUT_MS,
      },
      pool: { min: 0, max: 1 },
      acquireConnectionTimeout: CONNECTION_TIMEOUT_MS,
      compileSqlOnError: false,
      log: SILENT,
    });
    const queryOn =
      (runner: Pick<Knex, "raw">): PgQuery =>
      async (sql) =>
        (await runner.raw<{ rows: unknown[] }>(sql)).rows;
    return {
      query: queryOn(client),
      begin: async () => {
        const transaction = await client.transaction();
        return {
          query: queryOn(transaction),
          rollback: async () => {
            await transaction.rollback();
          },
        };
      },
      close: () => client.destroy(),
    };
  };

/** The driver the connector ships with: TLS always, verified against the
 * certificate authorities of AWS RDS. */
export const connect = connectWith({
  rejectUnauthorized: true,
  ca: awsCaBundle.ca,
});

/** A signed-in manager. Its failures are `ConnectorError`s. */
export type PgSession = {
  query: PgQuery;
  /** Runs `run` in one transaction, which is rolled back however `run`
   * ends, so nothing `run` did stays. */
  rolledBack: <T>(run: (query: PgQuery) => Promise<T>) => Promise<T>;
};

const mapped =
  (query: PgQuery): PgQuery =>
  async (sql) => {
    try {
      return await query(sql);
    } catch (error) {
      throw toConnectorError(error);
    }
  };

/** Runs `run` against `driver`, then closes it. */
export const withSession = async <T>(
  driver: PgDriver,
  logger: Logger,
  run: (session: PgSession) => Promise<T>
): Promise<T> => {
  const session: PgSession = {
    query: mapped(driver.query),
    rolledBack: async (inTransaction) => {
      const transaction = await driver.begin().catch((error: unknown) => {
        throw toConnectorError(error);
      });
      try {
        return await inTransaction(mapped(transaction.query));
      } finally {
        // A rollback that fails still leaves nothing behind: PostgreSQL
        // drops an open transaction when its connection closes, which
        // happens next.
        await transaction
          .rollback()
          .catch((error: unknown) =>
            logger.error(
              { failure: toConnectorError(error).data },
              "failed to roll back the PostgreSQL transaction"
            )
          );
      }
    },
  };
  try {
    return await run(session);
  } finally {
    await driver
      .close()
      .catch((error: unknown) =>
        logger.error(
          { failure: toConnectorError(error).data },
          "failed to close the PostgreSQL connection"
        )
      );
  }
};
