import type { GcpAuditLogQuery } from "@p0security/connector-core";

import { assertProjectId, auditLogName, filterString } from "../logging.ts";

/**
 * Cloud Logging rejects a filter longer than 20,000 characters. The
 * permission clause is left out, and narrowed in the connector instead,
 * when it would take the filter past this.
 */
export const MAX_FILTER_LENGTH = 18_000;

/** The Cloud Audit Logs a grant's activity can land in. */
export const AUDIT_LOGS = [
  "activity",
  "data_access",
  "system_event",
  "policy",
] as const;

const PRINCIPAL = "protoPayload.authenticationInfo.principalEmail";
const DELEGATOR =
  "protoPayload.authenticationInfo.serviceAccountDelegationInfo.firstPartyPrincipal.principalEmail";

const anyOf = (clauses: string[]) =>
  clauses.length === 1 ? clauses[0]! : `(${clauses.join(" OR ")})`;

/**
 * The `entries.list` filter for a `gcp-audit` query: the audit logs, the
 * principal (acting itself, or impersonating a service account), the window
 * and, while the filter stays short enough, the permissions. Resource
 * prefixes are narrowed in the connector.
 */
export const composeFilter = (query: GcpAuditLogQuery) => {
  const projectId = assertProjectId(query.projectId);
  const email = filterString(query.principalEmail);
  const clauses = [
    `logName=${anyOf(AUDIT_LOGS.map((log) => filterString(auditLogName(projectId, log))))}`,
    `(${PRINCIPAL}=${email} OR ${DELEGATOR}=${email})`,
    `timestamp>=${filterString(query.window.start)}`,
    `timestamp<${filterString(query.window.end)}`,
  ];
  const base = clauses.join("\n");
  if (!query.permissions || query.permissions.length === 0) {
    return { filter: base, permissionsPushedDown: false };
  }
  const permissions = `protoPayload.authorizationInfo.permission=${anyOf(
    query.permissions.map(filterString)
  )}`;
  const filter = `${base}\n${permissions}`;
  return filter.length <= MAX_FILTER_LENGTH
    ? { filter, permissionsPushedDown: true }
    : { filter: base, permissionsPushedDown: false };
};
