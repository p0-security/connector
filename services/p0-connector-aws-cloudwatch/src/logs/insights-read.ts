import {
  ConnectorError,
  type Gap,
  type LogEntry,
  type LogReadResult,
} from "@p0security/connector-core";

import type { Aws } from "../aws.ts";
import {
  FRESHNESS_QUERY,
  INSIGHTS_ROW_LIMIT,
  describeLogGroup,
  parseInsightsTime,
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

/** How far back the freshness query looks for the newest event. */
const FRESHNESS_LOOKBACK_MS = 60 * 60_000;

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

/** The `lag` gap, when the window reaches past what has been ingested. */
const lagGap = async (
  aws: Aws,
  plan: InsightsReadPlan,
  freshnessQueryId: string | undefined,
  deadline: number
): Promise<{ gaps: Gap[]; checkedThrough?: string }> => {
  const now = aws.now();
  if (plan.window.end <= now - LAG_HORIZON_MS) return { gaps: [] };
  let latest: number | undefined;
  if (freshnessQueryId) {
    const results = await pollQuery(
      aws,
      freshnessQueryId,
      Math.min(deadline, now + 2_000)
    );
    if (results.status === "complete") {
      latest = parseInsightsTime(results.rows[0]?.latest);
    }
  }
  if (latest !== undefined && latest >= plan.window.end) {
    return { gaps: [], checkedThrough: iso(latest) };
  }
  const checkedThrough = latest === undefined ? undefined : iso(latest);
  return {
    gaps: [
      {
        kind: "lag",
        ...(checkedThrough ? { checkedThrough } : {}),
        message: `${plan.label} logs can arrive up to 15 minutes late, so recent activity may still be arriving.`,
      },
    ],
    ...(checkedThrough ? { checkedThrough } : {}),
  };
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
 * returned with a `truncated` gap. When a slice completes and more remain,
 * the next is started before returning `more`, so the next call only polls.
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
      const lag = await lagGap(aws, plan, undefined, deadline);
      return {
        entries: [],
        state: "done",
        gaps: [...gaps, ...lag.gaps],
      };
    }
    const slice: Slice = [start, end];
    const q = await startQuery(
      aws,
      plan.logGroupName,
      plan.queryString,
      ...slice
    );
    const f =
      plan.window.end > now - LAG_HORIZON_MS
        ? await startQuery(
            aws,
            plan.logGroupName,
            FRESHNESS_QUERY,
            now - FRESHNESS_LOOKBACK_MS,
            now
          )
        : undefined;
    state = { q, s: slice, r: [], ...(f ? { f } : {}) };
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

    const entries = plan.toEntries(results.rows, {
      start: sliceStart,
      end: sliceEnd,
    });
    if (full) {
      gaps.push({
        kind: "truncated",
        start: iso(sliceStart),
        end: iso(sliceEnd),
        message: `More than ${INSIGHTS_ROW_LIMIT.toLocaleString("en-US")} ${plan.label} entries fell in one minute; only some are shown.`,
      });
    }

    const [next, ...rest] = state.r;
    if (next) {
      state = {
        ...state,
        q: await startQuery(aws, plan.logGroupName, plan.queryString, ...next),
        s: next,
        r: rest,
      };
      return {
        entries,
        state: "more",
        cursor: encodeCursor(plan.hash, state),
        gaps,
      };
    }

    const lag = await lagGap(aws, plan, state.f, deadline);
    return {
      entries,
      state: "done",
      gaps: [...gaps, ...lag.gaps],
      ...(lag.checkedThrough ? { checkedThrough: lag.checkedThrough } : {}),
    };
  }
};
