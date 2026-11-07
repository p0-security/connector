import type {
  GcpAuditLogQuery,
  LogEntry,
  LogReadResult,
} from "@p0security/connector-core";

import { entryMatches, isAuditLogEntry, toLogEntry } from "../audit/entries.ts";
import { composeFilter } from "../audit/filter.ts";
import type { Logging } from "../logging.ts";
import { queryHash } from "./cursor.ts";
import { readPages } from "./paged-read.ts";

export const toAuditEntries =
  (query: GcpAuditLogQuery) =>
  (raw: unknown[]): LogEntry[] => {
    const window = {
      start: Date.parse(query.window.start),
      end: Date.parse(query.window.end),
    };
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
      filter: composeFilter(query).filter,
      window: {
        start: Date.parse(query.window.start),
        end: Date.parse(query.window.end),
      },
      hash: queryHash(query),
      toEntries: toAuditEntries(query),
      label: "Cloud Audit",
    },
    cursor
  );
