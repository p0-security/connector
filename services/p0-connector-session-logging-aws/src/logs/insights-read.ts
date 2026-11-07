import {
  ConnectorError,
  type Gap,
  type LogEntry,
  type LogReadResult,
} from "@p0security/connector-core";

import type { Aws } from "../aws.ts";
import {
  INSIGHTS_ROW_LIMIT,
  describeLogGroup,
  pollQuery,
  startQuery,
} from "../insights.ts";
import {
  type CursorState,
  type Slice,
  decodeCursor,
  encodeCursor,
} from "./cursor.ts";

/** A slice this short that still fills a result is reported as truncated
 * rather than split again. */
export const MIN_SLICE_MS = 60_000;

/** How long one read call polls before it hands back a `running` cursor,
 * inside the control plane's 30 s budget. */
export const READ_BUDGET_MS = 20_000;

/** How late CloudWatch may still receive an event; a window ending later
 * than this before now may be missing entries. */
export const LAG_HORIZON_MS = 15 * 60_000;

/**
 * The most entry JSON one read returns. Lambda caps a synchronous response
 * at 6 MiB, and a slice's rows (up to 10,000 CloudTrail events, each with
 * its raw event) can be several times that, so a slice that doesn't fit is
 * returned over several reads. The rest of the 6 MiB is left for the gaps,
 * the cursor and tRPC's envelope.
 */
export const RESPONSE_BYTE_BUDGET = 4 * 1024 * 1024;

/** One Logs Insights read: the group, the query, and how to turn rows into entries. */
export type InsightsReadPlan = {
  logGroupName: string;
  queryString: string;
  /** The window as requested, in epoch ms. */
  window: { start: number; end: number };
  /** Identifies the query, for the cursor. */
  hash: string;
  /**
   * Rows to entries, narrowed to the query and to `bounds`, the slice the
   * rows came from: Insights works to the second, so neighbouring slices
   * can share an event.
   */
  toEntries: (
    rows: Record<string, string>[],
    bounds: { start: number; end: number }
  ) => LogEntry[];
  /** What to report when the log group doesn't exist. */
  missingGroup: Gap;
  /** Names the logs in gap messages: "CloudTrail", "Database". */
  label: string;
};

const iso = (ms: number) => new Date(ms).toISOString();

const retentionGap = (
  plan: InsightsReadPlan,
  retentionInDays: number | undefined,
  now: number
): Gap[] => {
  if (retentionInDays === undefined) return [];
  const retainedFrom = now - retentionInDays * 86_400_000;
  return plan.window.start < retainedFrom
    ? [
        {
          kind: "retention",
          retainedFrom: iso(retainedFrom),
          message: `${plan.label} logs are kept for ${retentionInDays} days, so older entries are gone.`,
        },
      ]
    : [];
};

/**
 * The `lag` gap, when the window ends within {@link LAG_HORIZON_MS} of now.
 * CloudWatch gives no completeness watermark: the newest event in a group
 * says nothing about an older one still in transit, so no `checkedThrough`
 * is claimed.
 */
const lagGap = (plan: InsightsReadPlan, now: number): Gap[] =>
  plan.window.end > now - LAG_HORIZON_MS
    ? [
        {
          kind: "lag",
          message: `${plan.label} logs can arrive up to 15 minutes late, so recent activity may still be arriving.`,
        },
      ]
    : [];

/**
 * The entries from `offset` on that fit in {@link RESPONSE_BYTE_BUDGET},
 * and where the next read starts. At least one entry is taken, so a read
 * always makes progress.
 */
const takeWithinBudget = (entries: LogEntry[], offset: number) => {
  let bytes = 0;
  let next = offset;
  while (next < entries.length) {
    // The entry's JSON plus the comma between it and the next.
    const size = Buffer.byteLength(JSON.stringify(entries[next])) + 1;
    if (next > offset && bytes + size > RESPONSE_BYTE_BUDGET) break;
    bytes += size;
    next++;
  }
  return { page: entries.slice(offset, next), next };
};

const invalidCursor = () =>
  new ConnectorError({
    type: "validation_error",
    message: "The cursor reaches outside the query's window",
    payload: {},
  });

/** Every slice in a cursor must sit inside the query's current window. */
const assertWithin = (state: CursorState, start: number, end: number) => {
  for (const [s, e] of [state.s, ...state.r]) {
    if (!(s >= start && e <= end && s < e)) throw invalidCursor();
  }
};

/**
 * Reads a window through Logs Insights, a slice at a time.
 *
 * The first call starts one query over the whole window. A slice whose
 * results fill Insights' 10,000-row cap is split in half and both halves are
 * read instead, down to {@link MIN_SLICE_MS}; one that still overflows is
 * returned with a `truncated` gap. A slice whose entries don't fit in
 * {@link RESPONSE_BYTE_BUDGET} is returned over several reads. When a slice
 * completes and more remain, the next is started before returning `more`,
 * so the next call only polls.
 */
export const readInsights = async (
  aws: Aws,
  plan: InsightsReadPlan,
  cursor: string | undefined
): Promise<LogReadResult> => {
  const now = aws.now();
  const deadline = now + READ_BUDGET_MS;
  const start = plan.window.start;
  const end = Math.min(plan.window.end, now);
  const gaps: Gap[] = [];
  let state: CursorState;

  if (cursor === undefined) {
    const group = await describeLogGroup(aws, plan.logGroupName);
    if (!group) {
      return { entries: [], state: "done", gaps: [plan.missingGroup] };
    }
    gaps.push(...retentionGap(plan, group.retentionInDays, now));
    if (end <= start) {
      return {
        entries: [],
        state: "done",
        gaps: [...gaps, ...lagGap(plan, now)],
      };
    }
    const slice: Slice = [start, end];
    const q = await startQuery(
      aws,
      plan.logGroupName,
      plan.queryString,
      ...slice
    );
    state = { q, s: slice, r: [] };
  } else {
    state = decodeCursor(cursor, plan.hash);
    assertWithin(state, start, Math.max(end, start));
  }

  for (;;) {
    const results = await pollQuery(aws, state.q, deadline);
    if (results.status === "running") {
      return {
        entries: [],
        state: "running",
        cursor: encodeCursor(plan.hash, state),
        gaps,
      };
    }

    const [sliceStart, sliceEnd] = state.s;
    const full = results.rows.length >= INSIGHTS_ROW_LIMIT;
    if (full && sliceEnd - sliceStart > MIN_SLICE_MS) {
      const mid = Math.floor((sliceStart + sliceEnd) / 2);
      const first: Slice = [sliceStart, mid];
      state = {
        ...state,
        q: await startQuery(aws, plan.logGroupName, plan.queryString, ...first),
        s: first,
        r: [[mid, sliceEnd], ...state.r],
      };
      continue;
    }

    const offset = state.o ?? 0;
    const all = plan.toEntries(results.rows, {
      start: sliceStart,
      end: sliceEnd,
    });
    const { page: entries, next: rest } = takeWithinBudget(all, offset);
    if (full && offset === 0) {
      gaps.push({
        kind: "truncated",
        start: iso(sliceStart),
        end: iso(sliceEnd),
        message: `More than ${INSIGHTS_ROW_LIMIT.toLocaleString("en-US")} ${plan.label} entries fell in one minute; only some are shown.`,
      });
    }

    // The slice's entries didn't fit in one response: the next read polls
    // the same, finished query (Insights keeps its results) and carries on
    // from `rest`.
    if (rest < all.length) {
      return {
        entries,
        state: "more",
        cursor: encodeCursor(plan.hash, { ...state, o: rest }),
        gaps,
      };
    }

    const { o: _, ...sliceDone } = state;
    const [next, ...remaining] = sliceDone.r;
    if (next) {
      state = {
        ...sliceDone,
        q: await startQuery(aws, plan.logGroupName, plan.queryString, ...next),
        s: next,
        r: remaining,
      };
      return {
        entries,
        state: "more",
        cursor: encodeCursor(plan.hash, state),
        gaps,
      };
    }

    return {
      entries,
      state: "done",
      gaps: [...gaps, ...lagGap(plan, aws.now())],
    };
  }
};
