import {
  BatchExecuteStatementCommand,
  CancelStatementCommand,
  type ColumnMetadata,
  DescribeStatementCommand,
  ExecuteStatementCommand,
  type Field,
  GetStatementResultCommand,
  RedshiftDataClient,
} from "@aws-sdk/client-redshift-data";
import {
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
} from "@p0security/connector-core";

import type { InstallContext } from "../context.ts";

export type RedshiftSession = {
  /** Runs one statement and discards any rows. */
  execute: (sql: string, database?: string) => Promise<void>;
  /** Runs one statement and returns its rows, keyed by column name. */
  query: <T = Record<string, unknown>>(
    sql: string,
    database?: string
  ) => Promise<T[]>;
  /** Runs the statements in order, in one transaction. */
  batch: (sqls: string[], database?: string) => Promise<void>;
};

/** The first word or two of a statement, for logs and errors: never its
 * text, which names objects from the request. */
export const statementKind = (sql: string) =>
  sql.trim().split(/\s+/).slice(0, 2).join(" ").toUpperCase();

// Below the Lambda's 270 s timeout, so a slow statement is cancelled and
// reported, not cut off.
const STATEMENT_DEADLINE_MS = 240_000;

const POLL_INTERVALS_MS = [100, 250, 500, 1000, 2000];

const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

const SDK_ERROR_TYPES: Record<string, ConnectorErrorOptions["type"]> = {
  AccessDeniedException: "insufficient_privileges",
  ResourceNotFoundException: "object_not_found",
  ValidationException: "validation_error",
  ActiveStatementsExceededException: "rate_limited",
  ActiveSessionsExceededException: "rate_limited",
  ThrottlingException: "rate_limited",
  DatabaseConnectionException: "upstream_unavailable",
  InternalServerException: "upstream_unavailable",
};

/** Redshift's error text for a failed statement, matched in order. */
const STATEMENT_ERROR_TYPES: [RegExp, ConnectorErrorOptions["type"]][] = [
  [
    /permission denied|not authorized|must be superuser/i,
    "insufficient_privileges",
  ],
  [/cannot be dropped because/i, "dependency_violation"],
  [/already exists/i, "already_exists"],
  [/does not exist|not found/i, "object_not_found"],
];

/**
 * Maps a Data API failure to the error P0 shows. The message is AWS's or
 * Redshift's, which names objects but never holds a credential.
 */
export const toConnectorError = (
  error: unknown,
  sql?: string
): ConnectorError => {
  if (error instanceof ConnectorError) return error;
  const { name, message } = (error ?? {}) as {
    name?: string;
    message?: string;
  };
  return new ConnectorError({
    type: (name ? SDK_ERROR_TYPES[name] : undefined) ?? "upstream_unavailable",
    message: `Redshift Data API error: ${message ?? String(error)}`,
    payload: {
      ...(name ? { name } : {}),
      ...(sql ? { statement: statementKind(sql) } : {}),
    },
  });
};

const statementFailed = (error: string, sql: string) =>
  new ConnectorError({
    type:
      STATEMENT_ERROR_TYPES.find(([pattern]) => pattern.test(error))?.[1] ??
      "unknown",
    message: `Redshift error: ${error}`,
    payload: { statement: statementKind(sql) },
  });

const fieldValue = (field: Field): unknown => {
  if (field.isNull) return null;
  if (field.stringValue !== undefined) return field.stringValue;
  if (field.longValue !== undefined) return field.longValue;
  if (field.doubleValue !== undefined) return field.doubleValue;
  if (field.booleanValue !== undefined) return field.booleanValue;
  return field.blobValue;
};

const toRow = (columns: ColumnMetadata[], fields: Field[]) =>
  Object.fromEntries(
    fields.map((field, index) => [
      columns[index]?.name ?? String(index),
      fieldValue(field),
    ])
  );

export type DataApiDependencies = {
  client?: Pick<RedshiftDataClient, "send">;
  wait?: (ms: number) => Promise<void>;
  now?: () => number;
};

/**
 * A session on the install's target, signed in as the connector's execution
 * role: no `DbUser` and no secret, so the Data API signs in with
 * `GetClusterCredentialsWithIAM` or `redshift-serverless:GetCredentials`.
 * Each call is one Data API statement, so nothing is held open between
 * calls.
 */
export const newRedshiftSession = (
  install: InstallContext,
  logger: Logger,
  {
    client = new RedshiftDataClient({ region: install.region }),
    wait = sleep,
    now = Date.now,
  }: DataApiDependencies = {}
): RedshiftSession => {
  const { target } = install;
  const on =
    target.type === "provisioned"
      ? { ClusterIdentifier: target.name }
      : { WorkgroupName: target.name };

  const send = async <T>(call: () => Promise<T>, sql: string) => {
    try {
      return await call();
    } catch (error) {
      throw toConnectorError(error, sql);
    }
  };

  /** Polls until the statement settles, and cancels it at the deadline. */
  const settle = async (id: string, sql: string) => {
    const deadline = now() + STATEMENT_DEADLINE_MS;
    for (let poll = 0; ; poll++) {
      const statement = await send(
        () => client.send(new DescribeStatementCommand({ Id: id })),
        sql
      );
      switch (statement.Status) {
        case "FINISHED":
          return statement;
        case "FAILED":
        case "ABORTED":
          logger.error(
            { statement: statementKind(sql), status: statement.Status },
            "Redshift statement failed"
          );
          throw statementFailed(statement.Error ?? statement.Status, sql);
      }
      if (now() >= deadline) {
        await send(
          () => client.send(new CancelStatementCommand({ Id: id })),
          sql
        ).catch(() => undefined);
        throw new ConnectorError({
          type: "upstream_unavailable",
          message: "Redshift statement timed out",
          payload: { statement: statementKind(sql) },
        });
      }
      await wait(
        POLL_INTERVALS_MS[Math.min(poll, POLL_INTERVALS_MS.length - 1)]!
      );
    }
  };

  const run = async (sql: string, database: string) => {
    const { Id } = await send(
      () =>
        client.send(
          new ExecuteStatementCommand({ ...on, Database: database, Sql: sql })
        ),
      sql
    );
    const statement = await settle(Id!, sql);
    logger.debug(
      { statement: statementKind(sql), id: Id },
      "Redshift statement succeeded"
    );
    return { id: Id!, hasRows: !!statement.HasResultSet };
  };

  const rows = async (id: string, sql: string) => {
    const result: Record<string, unknown>[] = [];
    let columns: ColumnMetadata[] = [];
    let nextToken: string | undefined;
    do {
      const page = await send(
        () =>
          client.send(
            new GetStatementResultCommand({ Id: id, NextToken: nextToken })
          ),
        sql
      );
      columns = page.ColumnMetadata ?? columns;
      for (const fields of page.Records ?? []) {
        result.push(toRow(columns, fields));
      }
      nextToken = page.NextToken;
    } while (nextToken);
    return result;
  };

  return {
    execute: async (sql, database = install.database) => {
      await run(sql, database);
    },
    query: async <T>(sql: string, database = install.database) => {
      const { id, hasRows } = await run(sql, database);
      return (hasRows ? await rows(id, sql) : []) as T[];
    },
    batch: async (sqls, database = install.database) => {
      if (sqls.length === 0) return;
      const label = sqls.map(statementKind).join("; ");
      const { Id } = await send(
        () =>
          client.send(
            new BatchExecuteStatementCommand({
              ...on,
              Database: database,
              Sqls: sqls,
            })
          ),
        label
      );
      await settle(Id!, label);
    },
  };
};
