import {
  type CloudSqlLogQuery,
  ConnectorError,
  type LogEntry,
} from "@p0security/connector-core";

import { assertProjectId, auditLogName, filterString } from "../logging.ts";
import { type AuditLogEntry, isAuditLogEntry } from "./entries.ts";

/** A Cloud SQL instance ID. */
const INSTANCE_ID = /^[a-z][a-z0-9-]{0,97}$/;

const PERMISSION_DENIED = 7;

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

const tableMatches = (table: string, tables: readonly string[]) =>
  tables.some((t) => {
    const want = t.toLowerCase();
    const got = table.toLowerCase();
    return got === want || (!got.includes(".") && want.endsWith(`.${got}`));
  });

/** Whether an entry is the query's user's, on its database and tables. */
const cloudSqlMatches = (
  query: CloudSqlLogQuery,
  entry: AuditLogEntry,
  window: { start: number; end: number }
) => {
  const time = Date.parse(entry.timestamp ?? "");
  if (!(time >= window.start && time < window.end)) return false;
  const request = requestOf(entry);
  const iam = lower(query.iamEmail);
  const users = [query.dbUser, query.iamEmail].filter(
    (u): u is string => u !== undefined
  );
  const isLogin = !isPg(request) && !isMySql(request);
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
    tables.some((t) => tableMatches(t, query.tables!))
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
    result:
      entry.protoPayload?.status?.code === PERMISSION_DENIED
        ? "denied"
        : "allowed",
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
    const window = {
      start: Date.parse(query.window.start),
      end: Date.parse(query.window.end),
    };
    return raw.flatMap((entry) =>
      isAuditLogEntry(entry) && cloudSqlMatches(query, entry, window)
        ? [toEntry(query, entry)]
        : []
    );
  };
