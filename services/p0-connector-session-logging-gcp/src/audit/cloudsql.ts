import {
  type CloudSqlLogQuery,
  ConnectorError,
  type LogEntry,
} from "@p0security/connector-core";

import { assertProjectId, auditLogName, filterString } from "../logging.ts";
import { type PreciseWindow, inWindow, preciseWindow } from "../time.ts";
import { type AuditLogEntry, isAuditLogEntry, isDenied } from "./entries.ts";

/** A Cloud SQL instance ID. */
const INSTANCE_ID = /^[a-z][a-z0-9-]{0,97}$/;

/**
 * The `entries.list` filter for a `cloudsql` query: the instance's Data
 * Access entries (pgAudit and MySQL audit records, and IAM logins) for the
 * database user or IAM account, in the window. Database and tables are
 * narrowed in the connector.
 */
export const composeCloudSqlFilter = (query: CloudSqlLogQuery) => {
  const projectId = assertProjectId(query.projectId);
  if (!INSTANCE_ID.test(query.instanceId)) {
    throw new ConnectorError({
      type: "validation_error",
      message: `${query.instanceId} isn't a Cloud SQL instance ID`,
      payload: { instanceId: query.instanceId },
    });
  }
  const who = [
    ...[query.dbUser, query.iamEmail]
      .filter((u): u is string => u !== undefined)
      .map((u) => `protoPayload.request.user=${filterString(u)}`),
    ...(query.iamEmail === undefined
      ? []
      : [
          `protoPayload.request.gcpIamAccount=${filterString(query.iamEmail)}`,
          `protoPayload.authenticationInfo.principalEmail=${filterString(query.iamEmail)}`,
        ]),
  ];
  return [
    `logName=${filterString(auditLogName(projectId, "data_access"))}`,
    'resource.type="cloudsql_database"',
    `resource.labels.database_id=${filterString(`${projectId}:${query.instanceId}`)}`,
    `(${who.join(" OR ")})`,
    `timestamp>=${filterString(query.window.start)}`,
    `timestamp<${filterString(query.window.end)}`,
  ].join("\n");
};

/** A Cloud SQL audit record (`PgAuditEntry` or `MysqlAuditEntry`). */
type AuditRequest = {
  "@type"?: string;
  user?: string;
  gcpIamAccount?: string;
  database?: string;
  command?: string;
  object?: string;
  objectType?: string;
  statement?: string;
  cmd?: string;
  query?: string;
  objects?: { db?: string; name?: string }[];
  [field: string]: unknown;
};

const requestOf = (entry: AuditLogEntry) =>
  (entry.protoPayload?.request ?? {}) as AuditRequest;

const isPg = (request: AuditRequest) =>
  request["@type"]?.endsWith("PgAuditEntry") ?? false;
const isMySql = (request: AuditRequest) =>
  request["@type"]?.endsWith("MysqlAuditEntry") ?? false;

const lower = (value: string | undefined) => value?.toLowerCase();

/** The tables a record names: pgAudit's object, MySQL's objects. */
const tablesOf = (request: AuditRequest) =>
  isPg(request)
    ? request.object
      ? [request.object]
      : []
    : (request.objects ?? [])
        .filter((o) => o.name)
        .map((o) => (o.db ? `${o.db}.${o.name}` : o.name!));

/**
 * A Postgres name's parts with pgAudit's quoting removed:
 * `public."Users"` is `["public", "Users"]`. Case is kept: `"Users"` and
 * `users` are different tables.
 */
const pgNameParts = (name: string) => {
  const parts: string[] = [];
  let part = "";
  let quoted = false;
  for (let i = 0; i < name.length; i++) {
    const c = name[i]!;
    if (c === '"' && quoted && name[i + 1] === '"') {
      part += '"';
      i++;
    } else if (c === '"') {
      quoted = !quoted;
    } else if (c === "." && !quoted) {
      parts.push(part);
      part = "";
    } else {
      part += c;
    }
  }
  parts.push(part);
  return parts;
};

/** A table name's parts: Postgres's as written, MySQL's case-insensitively. */
const nameParts = (name: string, postgres: boolean) =>
  postgres ? pgNameParts(name) : name.toLowerCase().split(".");

/** Whether a table is one of the query's (`schema.table` or `db.table`). A
 * table named without its schema matches on the name. */
const tableMatches = (
  table: string,
  tables: readonly string[],
  postgres: boolean
) => {
  const got = nameParts(table, postgres);
  return tables.some((t) => {
    const want = nameParts(t, postgres);
    return got.length === 1
      ? want.at(-1) === got[0]
      : got.length === want.length && got.every((p, i) => p === want[i]);
  });
};

/** The method of an IAM database login's audit entry. */
const LOGIN_METHOD = "cloudsql.instances.login";

/** Whether an entry is the query's user's, on its database and tables. */
const cloudSqlMatches = (
  query: CloudSqlLogQuery,
  entry: AuditLogEntry,
  window: PreciseWindow
) => {
  if (!inWindow(entry.timestamp, window)) return false;
  const request = requestOf(entry);
  const iam = lower(query.iamEmail);
  const users = [query.dbUser, query.iamEmail].filter(
    (u): u is string => u !== undefined
  );
  const isLogin = entry.protoPayload?.methodName === LOGIN_METHOD;
  // Any other Data Access entry on the instance (an API call) isn't
  // database access.
  if (!isLogin && !isPg(request) && !isMySql(request)) return false;
  const byUser = isLogin
    ? iam !== undefined &&
      lower(entry.protoPayload?.authenticationInfo?.principalEmail) === iam
    : users.includes(request.user ?? "") ||
      (iam !== undefined &&
        (lower(request.user) === iam || lower(request.gcpIamAccount) === iam));
  if (!byUser) return false;
  if (
    query.database !== undefined &&
    request.database &&
    request.database !== query.database
  ) {
    return false;
  }
  const tables = tablesOf(request);
  return (
    !query.tables ||
    tables.length === 0 ||
    tables.some((t) => tableMatches(t, query.tables!, isPg(request)))
  );
};

const toEntry = (query: CloudSqlLogQuery, entry: AuditLogEntry): LogEntry => {
  const request = requestOf(entry);
  const [table] = tablesOf(request);
  const action = isPg(request)
    ? request.command || "STATEMENT"
    : isMySql(request)
      ? (request.cmd ?? "QUERY").toUpperCase()
      : (entry.protoPayload?.methodName ?? "unknown");
  const resource =
    table ?? request.database ?? entry.protoPayload?.resourceName;
  return {
    id: entry.insertId!,
    time: new Date(entry.timestamp!).toISOString(),
    action,
    ...(resource ? { resource } : {}),
    result: isDenied(entry) ? "denied" : "allowed",
    principal:
      request.user ??
      request.gcpIamAccount ??
      entry.protoPayload?.authenticationInfo?.principalEmail ??
      query.dbUser ??
      query.iamEmail!,
    raw: entry,
  };
};

export const toCloudSqlEntries =
  (query: CloudSqlLogQuery) =>
  (raw: unknown[]): LogEntry[] => {
    const window = preciseWindow(query.window);
    return raw.flatMap((entry) =>
      isAuditLogEntry(entry) && cloudSqlMatches(query, entry, window)
        ? [toEntry(query, entry)]
        : []
    );
  };
