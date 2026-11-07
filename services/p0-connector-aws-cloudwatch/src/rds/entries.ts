import type { LogEntry, RdsLogQuery } from "@p0security/connector-core";
import { createHash } from "node:crypto";

import { parseInsightsTime } from "../insights.ts";
import {
  type MySqlAuditRecord,
  type PgAuditRecord,
  parseMySqlAuditLine,
  parsePgAuditLine,
} from "./parse.ts";

/** MySQL errors that mean the statement was refused for lack of privilege. */
const ACCESS_DENIED_CODES = new Set([1044, 1045, 1142, 1143, 1227, 1370]);

/**
 * CloudWatch log events have no ID of their own, so an entry's ID is a hash
 * of the stream, time and line: stable across reads, so P0 can dedupe.
 */
const entryId = (row: Record<string, string>) =>
  createHash("sha256")
    .update(
      `${row["@logStream"] ?? ""}\n${row["@timestamp"] ?? ""}\n${row["@message"] ?? ""}`
    )
    .digest("hex")
    .slice(0, 32);

const lower = (value: string) => value.toLowerCase();

/** Whether a table is one of the query's (`schema.table` or `db.table`),
 * case-insensitively. A table named without its schema matches on the name. */
const tableMatches = (table: string, tables: readonly string[]) =>
  tables.some((t) => {
    const want = lower(t);
    const got = lower(table);
    return got === want || (!got.includes(".") && want.endsWith(`.${got}`));
  });

const pgMatches = (query: RdsLogQuery, record: PgAuditRecord) =>
  record.user === query.dbUser &&
  (query.database === undefined || record.database === query.database) &&
  (!query.tables ||
    record.objectName === "" ||
    tableMatches(record.objectName, query.tables));

/** The table a MySQL record names, for READ and WRITE (table) events. */
const mySqlTable = (record: MySqlAuditRecord) =>
  record.operation === "READ" || record.operation === "WRITE"
    ? record.database
      ? `${record.database}.${record.object}`
      : record.object
    : undefined;

const mySqlMatches = (query: RdsLogQuery, record: MySqlAuditRecord) => {
  const table = mySqlTable(record);
  return (
    record.user === query.dbUser &&
    (query.database === undefined ||
      record.database === "" ||
      record.database === query.database) &&
    (!query.tables || !table || tableMatches(table, query.tables))
  );
};

const mySqlAction = (record: MySqlAuditRecord) =>
  record.operation === "QUERY"
    ? (/^\s*(\w+)/.exec(record.object)?.[1]?.toUpperCase() ?? "QUERY")
    : record.operation;

/**
 * Parses, narrows and normalizes Insights rows from an RDS audit log group.
 * Lines that aren't audit records (connection notices, other Postgres
 * logging) are dropped.
 */
export const toRdsEntries =
  (query: RdsLogQuery) =>
  (
    rows: Record<string, string>[],
    bounds: { start: number; end: number }
  ): LogEntry[] => {
    const start = Math.max(Date.parse(query.window.start), bounds.start);
    const end = Math.min(Date.parse(query.window.end), bounds.end);
    return rows.flatMap((row): LogEntry[] => {
      const message = row["@message"] ?? "";
      const timestamp = parseInsightsTime(row["@timestamp"]);
      if (timestamp === undefined || timestamp < start || timestamp >= end) {
        return [];
      }
      const base = {
        id: entryId(row),
        time: new Date(timestamp).toISOString(),
        principal: query.dbUser,
      };
      if (query.engine === "postgres") {
        const record = parsePgAuditLine(message);
        if (!record || !pgMatches(query, record)) return [];
        return [
          {
            ...base,
            action: record.command || record.class,
            resource: record.objectName || record.database,
            result: "allowed",
            raw: { message, logStream: row["@logStream"], ...record },
          },
        ];
      }
      const record = parseMySqlAuditLine(message);
      if (!record || !mySqlMatches(query, record)) return [];
      const resource = mySqlTable(record) ?? record.database;
      return [
        {
          ...base,
          action: mySqlAction(record),
          ...(resource ? { resource } : {}),
          result: ACCESS_DENIED_CODES.has(record.retcode)
            ? "denied"
            : "allowed",
          raw: { message, logStream: row["@logStream"], ...record },
        },
      ];
    });
  };
