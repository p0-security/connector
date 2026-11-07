import type { Gap, LogEntry, LogReadResult } from "@p0security/connector-core";

import { type Logging, statusOf, toConnectorError } from "../logging.ts";
import { decodeCursor, encodeCursor } from "./cursor.ts";

/** The most `entries.list` returns in a page. Large pages keep the
 * connector inside the project's 60 reads a minute. */
export const PAGE_SIZE = 1_000;

/** How long one read call keeps paging or backing off, inside the control
 * plane's 30 s budget. */
export const READ_BUDGET_MS = 20_000;

/** At most this many pages per call, so one read uses a few of the
 * project's 60 a minute. */
export const MAX_PAGES_PER_READ = 3;

/** `_Default` keeps Data Access and Policy Denied logs this long unless the
 * customer changes it. */
export const DEFAULT_RETENTION_DAYS = 30;

/** Cloud Logging usually has an entry within a minute or two. */
export const LAG_HORIZON_MS = 2 * 60_000;

const BACKOFF_MS = [1_000, 2_000, 4_000, 8_000];

/** One paged `entries.list` read. */
export type PagedReadPlan = {
  projectId: string;
  filter: string;
  /** The window as requested, in epoch ms. */
  window: { start: number; end: number };
  /** Identifies the query, for the cursor. */
  hash: string;
  /** Raw entries to entries, narrowed to the query. */
  toEntries: (raw: unknown[]) => LogEntry[];
  /** Names the logs in gap messages. */
  label: string;
};

const iso = (ms: number) => new Date(ms).toISOString();

const windowGaps = (plan: PagedReadPlan, now: number): Gap[] => {
  const gaps: Gap[] = [];
  const retainedFrom = now - DEFAULT_RETENTION_DAYS * 86_400_000;
  if (plan.window.start < retainedFrom) {
    gaps.push({
      kind: "retention",
      retainedFrom: iso(retainedFrom),
      message: `${plan.label} Data Access and Policy Denied logs are kept for ${DEFAULT_RETENTION_DAYS} days by default, so older entries may be gone.`,
    });
  }
  if (plan.window.end > now - LAG_HORIZON_MS) {
    gaps.push({
      kind: "lag",
      message: `${plan.label} logs can arrive a few minutes late, so recent activity may still be arriving.`,
    });
  }
  return gaps;
};

/**
 * Reads up to {@link MAX_PAGES_PER_READ} pages, oldest first, stopping early
 * once a page yields entries. A 429 is retried with backoff; when the budget
 * runs out first, what was read so far comes back with `state: "more"` and a
 * cursor at the page that was throttled.
 */
export const readPages = async (
  logging: Logging,
  plan: PagedReadPlan,
  cursor: string | undefined
): Promise<LogReadResult> => {
  const now = logging.now();
  const deadline = now + READ_BUDGET_MS;
  let pageToken =
    cursor === undefined ? undefined : decodeCursor(cursor, plan.hash);
  const gaps = cursor === undefined ? windowGaps(plan, now) : [];
  const entries: LogEntry[] = [];
  let retries = 0;

  for (let page = 0; page < MAX_PAGES_PER_READ;) {
    let response;
    try {
      response = await logging.listEntries({
        resourceNames: [`projects/${plan.projectId}`],
        filter: plan.filter,
        orderBy: "timestamp asc",
        pageSize: PAGE_SIZE,
        ...(pageToken ? { pageToken } : {}),
      });
    } catch (error) {
      if (statusOf(error) !== 429) throw toConnectorError(error);
      const backoff = BACKOFF_MS[Math.min(retries++, BACKOFF_MS.length - 1)]!;
      if (logging.now() + backoff > deadline) {
        return {
          entries,
          state: "more",
          cursor: encodeCursor(plan.hash, pageToken),
          gaps,
        };
      }
      await logging.wait(backoff);
      continue;
    }
    page++;
    entries.push(...plan.toEntries(response.entries ?? []));
    pageToken = response.nextPageToken || undefined;
    if (!pageToken) return { entries, state: "done", gaps };
    if (entries.length > 0 || logging.now() >= deadline) break;
  }
  return {
    entries,
    state: "more",
    cursor: encodeCursor(plan.hash, pageToken),
    gaps,
  };
};
