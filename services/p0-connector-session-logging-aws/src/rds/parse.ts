/**
 * Parsers for the database audit lines RDS exports to CloudWatch Logs.
 *
 * Postgres (pgaudit): the `log_line_prefix` carries the user and database
 * as `%u@%d` (RDS's default prefix is `%t:%r:%u@%d:[%p]:`), and the audit
 * record follows as CSV after `AUDIT: `:
 *
 *     2026-11-01 10:15:42 UTC:10.0.1.23(53422):p0_alice@app:[12345]:LOG:  AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,"select * from users",<not logged>
 *
 * MySQL (the MariaDB audit plugin on RDS, Advanced Auditing on Aurora): one
 * CSV record per line, with `'`-quoted values:
 *
 *     20261101 10:15:42,ip-10-0-1-5,p0_alice,10.0.1.23,1234,5678,QUERY,app,'SELECT * FROM users',0
 */
import { escapeRegex } from "../patterns.ts";

/** Splits one CSV record. `quote` encloses a field; inside one, a doubled
 * quote escapes it. With `'` (the MySQL audit format) a backslash also
 * escapes the next character; pgaudit's `"` CSV keeps backslashes as they
 * are. */
export const splitCsv = (line: string, quote: '"' | "'") => {
  const fields: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (quoted) {
      if (quote === "'" && c === "\\" && i + 1 < line.length) {
        field += line[++i];
      } else if (c === quote && line[i + 1] === quote) {
        field += quote;
        i++;
      } else if (c === quote) {
        quoted = false;
      } else {
        field += c;
      }
    } else if (c === quote && field === "") {
      quoted = true;
    } else if (c === ",") {
      fields.push(field);
      field = "";
    } else {
      field += c;
    }
  }
  fields.push(field);
  return fields;
};

export type PgAuditRecord = {
  user: string;
  database: string;
  /** `SESSION` or `OBJECT`. */
  auditType: string;
  statementId: string;
  substatementId: string;
  /** `READ`, `WRITE`, `DDL`, `ROLE`, `FUNCTION`, `MISC`. */
  class: string;
  /** `SELECT`, `UPDATE`, `CREATE TABLE`, … */
  command: string;
  objectType: string;
  objectName: string;
  statement: string;
};

/** The `%u@%d:[%p]:` part of the prefix. The client address before it may
 * hold colons (IPv6), so it's found by its shape rather than by position. */
const PREFIX_USER_DB = /:([^:@\s]+)@([^:@\s]*):\[\d+\]:/;

/**
 * The same part for a known user. A user or database name may hold `@`
 * (`alice@example.com`), which leaves `%u@%d` ambiguous on its own; the
 * user it's read for settles where the user ends.
 */
const prefixFor = (user: string) =>
  new RegExp(`:(${escapeRegex(user)})@([^:\\s]*):\\[\\d+\\]:`);

const AUDIT_MARKER = "AUDIT: ";

/**
 * A pgaudit line, or undefined for any other Postgres log line. Given
 * `user`, only that user's lines are read, whatever `@`s its name or the
 * database's holds.
 */
export const parsePgAuditLine = (
  message: string,
  user?: string
): PgAuditRecord | undefined => {
  const prefix = (user === undefined ? PREFIX_USER_DB : prefixFor(user)).exec(
    message
  );
  const audit = message.indexOf(AUDIT_MARKER);
  if (!prefix || audit < 0 || audit < prefix.index) return undefined;
  const fields = splitCsv(message.slice(audit + AUDIT_MARKER.length), '"');
  if (fields.length < 8) return undefined;
  const [
    auditType,
    statementId,
    substatementId,
    auditClass,
    command,
    objectType,
    objectName,
    statement,
  ] = fields as [
    string,
    string,
    string,
    string,
    string,
    string,
    string,
    string,
  ];
  return {
    user: prefix[1]!,
    database: prefix[2]!,
    auditType,
    statementId,
    substatementId,
    class: auditClass,
    command,
    objectType,
    objectName,
    statement,
  };
};

export type MySqlAuditRecord = {
  /** Epoch ms, when the line's own timestamp can be read. */
  time?: number;
  serverHost: string;
  user: string;
  host: string;
  connectionId: string;
  queryId: string;
  /** `CONNECT`, `DISCONNECT`, `QUERY`, `READ`, `WRITE`, … */
  operation: string;
  database: string;
  /** The statement for `QUERY`, the table for `READ`/`WRITE`. */
  object: string;
  retcode: number;
};

/** `20261101 10:15:42` (RDS MySQL) or epoch microseconds (Aurora MySQL). */
const parseMySqlTime = (value: string) => {
  if (/^\d{16}$/.test(value)) return Math.floor(Number(value) / 1000);
  const m = /^(\d{4})(\d\d)(\d\d) (\d\d:\d\d:\d\d)$/.exec(value);
  return m ? Date.parse(`${m[1]}-${m[2]}-${m[3]}T${m[4]}Z`) : undefined;
};

/** A MySQL audit line, or undefined for anything else. */
export const parseMySqlAuditLine = (
  message: string
): MySqlAuditRecord | undefined => {
  const fields = splitCsv(message.trim(), "'");
  if (fields.length < 10) return undefined;
  const [
    timestamp,
    serverHost,
    user,
    host,
    connectionId,
    queryId,
    operation,
    database,
    object,
    retcode,
  ] = fields as [
    string,
    string,
    string,
    string,
    string,
    string,
    string,
    string,
    string,
    string,
  ];
  const code = Number(retcode);
  if (!user || !operation || Number.isNaN(code)) return undefined;
  const time = parseMySqlTime(timestamp);
  return {
    ...(time !== undefined ? { time } : {}),
    serverHost,
    user,
    host,
    connectionId,
    queryId,
    operation,
    database,
    object,
    retcode: code,
  };
};
