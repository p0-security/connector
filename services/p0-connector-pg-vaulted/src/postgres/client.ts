import type { Logger } from "@p0security/connector-core";
import awsCaBundle from "aws-ssl-profiles";
import pg from "pg";

import type { Target } from "../context.ts";
import { toConnectorError } from "./errors.ts";

/**
 * Runs one statement and returns its rows. `$1`, `$2` and so on in `sql`
 * stand for `bindings`, which the server receives as parameters, apart from
 * the statement's text.
 */
export type PgQuery = (
  sql: string,
  bindings?: readonly string[]
) => Promise<unknown[]>;

/** An open transaction, until it is committed or rolled back. */
export type PgTransaction = {
  query: PgQuery;
  commit: () => Promise<void>;
  rollback: () => Promise<void>;
};

/**
 * The driver calls the connector makes, which is what stands in for
 * PostgreSQL in tests. A failure is whatever the driver throws.
 */
export type PgDriver = {
  query: PgQuery;
  begin: () => Promise<PgTransaction>;
  close: () => Promise<void>;
};

/** A target, and the manager's credential for it. */
export type ManagerSignIn = Target & { username: string; password: string };

/** Opens the driver. It connects on its first statement. */
export type Connect = (signIn: ManagerSignIn) => PgDriver;

const CONNECTION_TIMEOUT_MS = 10_000;
const STATEMENT_TIMEOUT_MS = 15_000;

/**
 * A driver that connects with `ssl`, as one connection per request. Only
 * the integration tests pass anything but {@link connect}'s TLS, to reach a
 * local database. No request can.
 *
 * It sends a statement's text as it is. The connector runs statements that
 * PostgreSQL built, whose literals can hold any character, so nothing
 * between the connector and the server may rewrite a statement.
 */
export const connectWith =
  (ssl: pg.ClientConfig["ssl"]): Connect =>
  ({ host, port, database, username, password }) => {
    const client = new pg.Client({
      host,
      port,
      database,
      user: username,
      password,
      ssl,
      connectionTimeoutMillis: CONNECTION_TIMEOUT_MS,
      statement_timeout: STATEMENT_TIMEOUT_MS,
    });
    // An error on an idle connection has no statement to reject, and would
    // end the process without a listener. The next statement fails instead.
    client.on("error", () => {});
    let connecting: Promise<unknown> | undefined;
    const query: PgQuery = async (sql, bindings = []) => {
      connecting ??= client.connect();
      await connecting;
      return (await client.query(sql, [...bindings])).rows;
    };
    const run = (sql: string) => async () => {
      await query(sql);
    };
    return {
      query,
      begin: async () => {
        await query("BEGIN");
        return { query, commit: run("COMMIT"), rollback: run("ROLLBACK") };
      },
      close: () => client.end(),
    };
  };

/** The driver the connector ships with: TLS always, verified against the
 * certificate authorities of AWS RDS. */
export const connect = connectWith({
  rejectUnauthorized: true,
  ca: awsCaBundle.ca,
});

type InTransaction<T> = (query: PgQuery) => Promise<T>;

/** A signed-in manager. Its failures are `ConnectorError`s. */
export type PgSession = {
  query: PgQuery;
  /** Runs `run` in one transaction, which is rolled back however `run`
   * ends, so nothing `run` did stays. */
  rolledBack: <T>(run: InTransaction<T>) => Promise<T>;
  /** Runs `run` in one transaction and commits it. When `run` or the commit
   * fails, the transaction is rolled back, so nothing `run` did stays, and
   * the failure is thrown. */
  committed: <T>(run: InTransaction<T>) => Promise<T>;
};

const mapped =
  (query: PgQuery): PgQuery =>
  async (sql, bindings) => {
    try {
      return await query(sql, bindings);
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
  const begin = () =>
    driver.begin().catch((error: unknown) => {
      throw toConnectorError(error);
    });
  // A rollback that fails still leaves nothing behind: PostgreSQL drops an
  // open transaction when its connection closes, which happens next.
  const rollBack = (transaction: PgTransaction) =>
    transaction
      .rollback()
      .catch((error: unknown) =>
        logger.error(
          { failure: toConnectorError(error).data },
          "failed to roll back the PostgreSQL transaction"
        )
      );
  const session: PgSession = {
    query: mapped(driver.query),
    rolledBack: async (inTransaction) => {
      const transaction = await begin();
      try {
        return await inTransaction(mapped(transaction.query));
      } finally {
        await rollBack(transaction);
      }
    },
    committed: async (inTransaction) => {
      const transaction = await begin();
      try {
        const result = await inTransaction(mapped(transaction.query));
        await transaction.commit().catch((error: unknown) => {
          throw toConnectorError(error);
        });
        return result;
      } catch (error) {
        await rollBack(transaction);
        throw error;
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
