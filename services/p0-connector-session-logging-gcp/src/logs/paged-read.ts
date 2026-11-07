import {
  ConnectorError,
  type Gap,
  type LogEntry,
  type LogReadResult,
} from "@p0security/connector-core";

import { type Logging, statusOf, toConnectorError } from "../logging.ts";
import { preciseTime } from "../time.ts";
import { type CursorState, decodeCursor, encodeCursor } from "./cursor.ts";

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

/** The filter and the narrowing for the window up to one end. */
export type PagedReadQuery = {
  filter: string;
  /** Raw entries to entries, narrowed to the query. */
  toEntries: (raw: unknown[]) => LogEntry[];
};

/** One paged `entries.list` read. */
export type PagedReadPlan = {
  projectId: string;
  /** The window as requested. */
  window: { start: string; end: string };
  /** Identifies the query, for the cursor. */
  hash: string;
  /** The filter and narrowing for the window ending at `end`, which is the
   * requested end on a first read and the end paging began with after. */
  forEnd: (end: string) => PagedReadQuery;
  /** Names the logs in gap messages. */
  label: string;
};

const iso = (ms: number) => new Date(ms).toISOString();

const windowGaps = (plan: PagedReadPlan, now: number): Gap[] => {
  const gaps: Gap[] = [];
  const retainedFrom = now - DEFAULT_RETENTION_DAYS * 86_400_000;
  if (Date.parse(plan.window.start) < retainedFrom) {
    gaps.push({
      kind: "retention",
      retainedFrom: iso(retainedFrom),
      message: `${plan.label} Data Access and Policy Denied logs are kept for ${DEFAULT_RETENTION_DAYS} days by default, so older entries may be gone.`,
    });
  }
  if (Date.parse(plan.window.end) > now - LAG_HORIZON_MS) {
    gaps.push({
      kind: "lag",
      message: `${plan.label} logs can arrive a few minutes late, so recent activity may still be arriving.`,
    });
  }
  return gaps;
};

/** The cursor's state, checked against the query's current window: its
 * end may not reach past the window's, nor before its start. */
const resume = (plan: PagedReadPlan, cursor: string): CursorState => {
  const state = decodeCursor(cursor, plan.hash);
  const end = preciseTime(state.end)!;
  if (
    end < preciseTime(plan.window.start)! ||
    end > preciseTime(plan.window.end)!
  ) {
    throw new ConnectorError({
      type: "validation_error",
      message: "The cursor reaches outside the query's window",
      payload: {},
    });
  }
  return state;
};

/**
 * Calls `entries.list`, giving up when `deadline` (epoch ms) passes: the
 * request is aborted and undefined is returned.
 */
const listBefore = async (
  logging: Logging,
  request: Parameters<Logging["listEntries"]>[0],
  deadline: number
) => {
  const remaining = deadline - logging.now();
  if (remaining <= 0) return undefined;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), remaining);
  try {
    return await logging.listEntries(request, controller.signal);
  } catch (error) {
    if (controller.signal.aborted) return undefined;
    throw error;
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Reads up to {@link MAX_PAGES_PER_READ} pages, oldest first, stopping early
 * once a page yields entries. A 429 is retried with backoff. When the budget
 * runs out first, whether backing off or waiting on a slow page, what was
 * read so far comes back with `state: "more"` and a cursor at the page that
 * wasn't read.
 *
 * Paging holds the window's end it began with (see {@link CursorState}): a
 * live grant's later activity is read by the next fresh read.
 */
export const readPages = async (
  logging: Logging,
  plan: PagedReadPlan,
  cursor: string | undefined
): Promise<LogReadResult> => {
  const now = logging.now();
  const deadline = now + READ_BUDGET_MS;
  const state: CursorState =
    cursor === undefined ? { end: plan.window.end } : resume(plan, cursor);
  const { filter, toEntries } = plan.forEnd(state.end);
  let pageToken = state.pageToken;
  const gaps = cursor === undefined ? windowGaps(plan, now) : [];
  const entries: LogEntry[] = [];
  let retries = 0;
  const more = (): LogReadResult => ({
    entries,
    state: "more",
    cursor: encodeCursor(plan.hash, {
      ...(pageToken ? { pageToken } : {}),
      end: state.end,
    }),
    gaps,
  });

  for (let page = 0; page < MAX_PAGES_PER_READ;) {
    let response;
    try {
      response = await listBefore(
        logging,
        {
          resourceNames: [`projects/${plan.projectId}`],
          filter,
          orderBy: "timestamp asc",
          pageSize: PAGE_SIZE,
          ...(pageToken ? { pageToken } : {}),
        },
        deadline
      );
    } catch (error) {
      if (statusOf(error) !== 429) throw toConnectorError(error);
      const backoff = BACKOFF_MS[Math.min(retries++, BACKOFF_MS.length - 1)]!;
      if (logging.now() + backoff > deadline) return more();
      await logging.wait(backoff);
      continue;
    }
    if (response === undefined) return more();
    page++;
    entries.push(...toEntries(response.entries ?? []));
    pageToken = response.nextPageToken || undefined;
    if (!pageToken) return { entries, state: "done", gaps };
    if (entries.length > 0 || logging.now() >= deadline) break;
  }
  return more();
};
