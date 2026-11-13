import type { GcpAuditLogQuery, LogEntry } from "@p0security/connector-core";

import { type PreciseWindow, inWindow } from "../time.ts";

/** The fields of a Cloud Audit Log entry the connector reads. */
export type AuditLogEntry = {
  insertId?: string;
  timestamp?: string;
  logName?: string;
  protoPayload?: {
    methodName?: string;
    resourceName?: string;
    status?: { code?: number; message?: string };
    authenticationInfo?: {
      principalEmail?: string;
      serviceAccountDelegationInfo?: {
        firstPartyPrincipal?: { principalEmail?: string };
      }[];
      [field: string]: unknown;
    };
    authorizationInfo?: {
      permission?: string;
      resource?: string;
      granted?: boolean;
      [field: string]: unknown;
    }[];
    request?: Record<string, unknown>;
    [field: string]: unknown;
  };
  [field: string]: unknown;
};

/** gRPC's PERMISSION_DENIED. */
const PERMISSION_DENIED = 7;

const lower = (value: string | undefined) => value?.toLowerCase();

/** The principal acted, itself or by impersonating a service account. */
export const actedAs = (entry: AuditLogEntry, email: string) => {
  const auth = entry.protoPayload?.authenticationInfo;
  const target = email.toLowerCase();
  return (
    lower(auth?.principalEmail) === target ||
    (auth?.serviceAccountDelegationInfo ?? []).some(
      (d) => lower(d.firstPartyPrincipal?.principalEmail) === target
    )
  );
};

/** Drops a full resource name's `//service.googleapis.com/` part. */
const relativeName = (name: string) => name.replace(/^\/\/[^/]+\//, "");

/** The resource names an entry acts on. */
const resourceNames = (entry: AuditLogEntry) =>
  [
    entry.protoPayload?.resourceName,
    ...(entry.protoPayload?.authorizationInfo ?? []).map((a) => a.resource),
  ]
    .filter((name): name is string => typeof name === "string" && name !== "")
    .map(relativeName);

const underPrefix = (name: string, prefix: string) =>
  name === prefix || name.startsWith(`${prefix}/`);

/**
 * Whether an entry belongs to the query, checked in full whatever the filter
 * already did: principal, window, permissions and resource prefixes.
 *
 * An entry must hold one of the query's permissions when it has any. A
 * prefix that is the queried project itself admits every entry, since the
 * read covers only that project; any other prefix must contain one of the
 * entry's resource names, and an entry naming no resource passes, since
 * nothing shows it's outside the grant.
 */
export const entryMatches = (
  query: GcpAuditLogQuery,
  entry: AuditLogEntry,
  window: PreciseWindow
) => {
  if (!actedAs(entry, query.principalEmail)) return false;
  if (!inWindow(entry.timestamp, window)) return false;

  if (query.permissions && query.permissions.length > 0) {
    const granted = new Set(query.permissions);
    const held = (entry.protoPayload?.authorizationInfo ?? []).map(
      (a) => a.permission
    );
    if (!held.some((p) => p !== undefined && granted.has(p))) return false;
  }

  if (query.resourcePrefixes && query.resourcePrefixes.length > 0) {
    const prefixes = query.resourcePrefixes.map(relativeName);
    if (prefixes.includes(`projects/${query.projectId}`)) return true;
    const names = resourceNames(entry);
    if (
      names.length > 0 &&
      !names.some((name) => prefixes.some((p) => underPrefix(name, p)))
    ) {
      return false;
    }
  }
  return true;
};

/** Refused: by IAM on every check, by status, or by an IAM deny policy. */
export const isDenied = (entry: AuditLogEntry) => {
  const checks = entry.protoPayload?.authorizationInfo ?? [];
  return (
    (checks.length > 0 && checks.every((a) => a.granted === false)) ||
    entry.protoPayload?.status?.code === PERMISSION_DENIED ||
    (entry.logName?.endsWith("cloudaudit.googleapis.com%2Fpolicy") ?? false)
  );
};

export const toLogEntry = (entry: AuditLogEntry): LogEntry => {
  const resource = entry.protoPayload?.resourceName;
  return {
    id: entry.insertId!,
    time: new Date(entry.timestamp!).toISOString(),
    action: entry.protoPayload?.methodName ?? "unknown",
    ...(resource ? { resource } : {}),
    result: isDenied(entry) ? "denied" : "allowed",
    principal:
      entry.protoPayload?.authenticationInfo?.principalEmail ?? "unknown",
    raw: entry,
  };
};

/** An entry with the fields every `LogEntry` needs. */
export const isAuditLogEntry = (entry: unknown): entry is AuditLogEntry =>
  typeof entry === "object" &&
  entry !== null &&
  typeof (entry as AuditLogEntry).insertId === "string" &&
  !Number.isNaN(Date.parse((entry as AuditLogEntry).timestamp ?? ""));
