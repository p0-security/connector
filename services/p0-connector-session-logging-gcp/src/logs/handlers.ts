import {
  ConnectorError,
  type LogQuery,
  type LogSourceHandlers,
} from "@p0security/connector-core";

import { type LoggingDependencies, newLogging } from "../logging.ts";
import { readCloudSql } from "./cloudsql.ts";
import { readGcpAudit } from "./gcp-audit.ts";

const unsupported = (query: LogQuery) =>
  new ConnectorError({
    type: "validation_error",
    message: `The gcp-cloud-logging connector doesn't read ${query.source} logs`,
    payload: { source: query.source },
  });

/**
 * The `logs` route: Cloud Audit Logs, and Cloud SQL database audit entries. There's
 * nothing to check for `gcp-audit`: whether Data Access logs are on is read
 * by P0 itself, through the gcloud integration.
 */
export const newLogHandlers = (
  dependencies: LoggingDependencies = {}
): LogSourceHandlers => ({
  read: async ({ query, cursor }) => {
    switch (query.source) {
      case "gcp-audit":
        return readGcpAudit(newLogging(dependencies), query, cursor);
      case "cloudsql":
        return readCloudSql(newLogging(dependencies), query, cursor);
      default:
        throw unsupported(query);
    }
  },
  check: async ({ target }) => {
    switch (target.source) {
      // P0 doesn't check whether database auditing is on (spec §14).
      case "gcp-audit":
      case "cloudsql":
        return { gaps: [] };
      default:
        throw unsupported(target);
    }
  },
});
