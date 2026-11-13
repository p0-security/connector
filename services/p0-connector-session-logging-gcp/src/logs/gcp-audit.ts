import type {
  GcpAuditLogQuery,
  LogEntry,
  LogReadResult,
} from "@p0security/connector-core";

import { entryMatches, isAuditLogEntry, toLogEntry } from "../audit/entries.ts";
import { composeFilter } from "../audit/filter.ts";
import type { Logging } from "../logging.ts";
import { preciseWindow } from "../time.ts";
import { queryHash } from "./cursor.ts";
import { readPages } from "./paged-read.ts";

export const toAuditEntries =
  (query: GcpAuditLogQuery) =>
  (raw: unknown[]): LogEntry[] => {
    const window = preciseWindow(query.window);
    return raw.flatMap((entry) =>
      isAuditLogEntry(entry) && entryMatches(query, entry, window)
        ? [toLogEntry(entry)]
        : []
    );
  };

export const readGcpAudit = (
  logging: Logging,
  query: GcpAuditLogQuery,
  cursor: string | undefined
): Promise<LogReadResult> =>
  readPages(
    logging,
    {
      projectId: query.projectId,
      window: query.window,
      hash: queryHash(query),
      forEnd: (end) => {
        const paged = { ...query, window: { ...query.window, end } };
        return {
          filter: composeFilter(paged).filter,
          toEntries: toAuditEntries(paged),
        };
      },
      label: "Cloud Audit",
    },
    cursor
  );
