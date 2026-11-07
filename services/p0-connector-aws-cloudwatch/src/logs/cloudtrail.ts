import {
  type CloudTrailLogQuery,
  ConnectorError,
  type LogEntry,
  type LogReadResult,
  type Logger,
  type NotDeliveredGap,
} from "@p0security/connector-core";

import type { Aws } from "../aws.ts";
import { eventMatches, parseEvent, toLogEntry } from "../cloudtrail/events.ts";
import { composeInsightsQuery } from "../cloudtrail/query.ts";
import {
  deliveredDataEventTypes,
  findDeliveringTrail,
  missingDataEventTypes,
} from "../cloudtrail/trail.ts";
import { globToRegExp } from "../patterns.ts";
import { queryHash } from "./cursor.ts";
import { readInsights } from "./insights-read.ts";

const requireLogGroup = (logGroupName: string | undefined) => {
  if (logGroupName === undefined) {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "A CloudTrail read needs the item's CloudTrail log group (logGroupName)",
      payload: {},
    });
  }
  return logGroupName;
};

/** Parses, narrows and normalizes Insights rows; rows that aren't CloudTrail events are dropped. */
export const toCloudTrailEntries =
  (query: CloudTrailLogQuery) =>
  (
    rows: Record<string, string>[],
    bounds: { start: number; end: number }
  ): LogEntry[] => {
    const window = {
      start: Math.max(Date.parse(query.window.start), bounds.start),
      end: Math.min(Date.parse(query.window.end), bounds.end),
    };
    return rows.flatMap((row) => {
      const event = row["@message"] && parseEvent(row["@message"]);
      return event && eventMatches(query, event, window)
        ? [toLogEntry(event)]
        : [];
    });
  };

export const readCloudTrail = (
  aws: Aws,
  query: CloudTrailLogQuery,
  logGroupName: string | undefined,
  cursor: string | undefined
): Promise<LogReadResult> => {
  const group = requireLogGroup(logGroupName);
  return readInsights(
    aws,
    {
      logGroupName: group,
      queryString: composeInsightsQuery(query),
      window: {
        start: Date.parse(query.window.start),
        end: Date.parse(query.window.end),
      },
      hash: queryHash(query, group),
      toEntries: toCloudTrailEntries(query),
      missingGroup: {
        kind: "not-delivered",
        log: "cloudtrail",
        docsAnchor: "deliver-cloudtrail-to-cloudwatch-logs",
        message: `The CloudTrail log group ${group} doesn't exist, so no AWS activity can be read.`,
      },
      label: "CloudTrail",
    },
    cursor
  );
};

/** Whether any of a grant's action patterns can reach a service's data events. */
const reachesDataEvents = (
  actions: readonly string[] | undefined,
  type: ReturnType<typeof missingDataEventTypes>[number]
) =>
  (actions ?? []).some((pattern) => {
    const [prefix = "", name = "*"] = pattern.split(":");
    if (!globToRegExp(prefix, "i").test(type.prefix)) return false;
    // A wildcard in the action name can match a data action.
    return name.includes("*") || name.includes("?") || type.actions.test(name);
  });

/**
 * `not-delivered` gaps for the data events a CloudTrail target needs but the
 * trail behind the log group doesn't deliver. Only services the target's
 * action patterns name are checked; a target without actions (an
 * unnarrowed grant) gets no gap. When no trail in this account names the
 * group, the connector can't tell and reports nothing.
 */
export const checkCloudTrail = async (
  aws: Aws,
  target: CloudTrailLogQuery,
  logGroupName: string | undefined,
  logger: Logger
): Promise<NotDeliveredGap[]> => {
  const group = requireLogGroup(logGroupName);
  const types = missingDataEventTypes(new Set()).filter((type) =>
    reachesDataEvents(target.actions, type)
  );
  if (types.length === 0) return [];

  const trail = await findDeliveringTrail(aws, group);
  if (!trail) {
    logger.warn(
      { logGroupName: group },
      "no trail in this account delivers to the log group; data events not checked"
    );
    return [];
  }
  const delivered = await deliveredDataEventTypes(aws, trail);
  return types
    .filter((type) => !delivered.has(type.resourceType))
    .map((type) => ({
      kind: "not-delivered",
      log: "cloudtrail-data-events",
      service: type.eventSource,
      docsAnchor: "turn-on-cloudtrail-data-events",
      message:
        `The trail ${trail.Name ?? ""} doesn't deliver ${type.label} data events, so ${type.label} data access isn't shown.`.replace(
          "trail  ",
          "trail "
        ),
    }));
};
