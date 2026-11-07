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
import { readsOrWrites } from "../cloudtrail/services.ts";
import {
  type DataEventCoverage,
  deliveredDataEventTypes,
  findDeliveringTrail,
  missingDataEventTypes,
} from "../cloudtrail/trail.ts";
import { describeLogGroup } from "../insights.ts";
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

type DataEventType = ReturnType<typeof missingDataEventTypes>[number];

/**
 * Which of a service's data events a grant's action patterns can reach:
 * reads, writes, or undefined for none. A wildcard counts only when it can
 * match one of the service's data actions (`lambda:Get*` reaches none).
 */
const dataEventNeeds = (
  actions: readonly string[] | undefined,
  type: DataEventType
): DataEventCoverage | undefined => {
  let needs: DataEventCoverage | undefined;
  for (const pattern of actions ?? []) {
    const [prefix = "", name = "*"] = pattern.split(":");
    if (!globToRegExp(prefix, "i").test(type.prefix)) continue;
    const wildcard = name.includes("*") || name.includes("?");
    const names =
      "dataActions" in type
        ? type.dataActions.filter((action) =>
            wildcard
              ? globToRegExp(name, "i").test(action)
              : action.toLowerCase() === name.toLowerCase()
          )
        : wildcard || type.actions.test(name)
          ? [name]
          : [];
    for (const matched of names) {
      const n = readsOrWrites(matched);
      needs = {
        read: n.read || (needs?.read ?? false),
        write: n.write || (needs?.write ?? false),
      };
    }
  }
  return needs;
};

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
  const types = missingDataEventTypes(new Map()).flatMap((type) => {
    const needs = dataEventNeeds(target.actions, type);
    return needs ? [{ type, needs }] : [];
  });
  if (types.length === 0) return [];

  const described = await describeLogGroup(aws, group);
  const trail = await findDeliveringTrail(aws, group, described?.arn);
  if (!trail) {
    logger.warn(
      { logGroupName: group },
      "no trail in this account delivers to the log group; data events not checked"
    );
    return [];
  }
  const delivered = await deliveredDataEventTypes(aws, trail);
  return types.flatMap(({ type, needs }): NotDeliveredGap[] => {
    const coverage = delivered.get(type.resourceType);
    const missingReads = needs.read && !coverage?.read;
    const missingWrites = needs.write && !coverage?.write;
    if (!missingReads && !missingWrites) return [];
    const which =
      coverage && missingReads && !missingWrites
        ? "read "
        : coverage && missingWrites && !missingReads
          ? "write "
          : "";
    return [
      {
        kind: "not-delivered",
        log: "cloudtrail-data-events",
        service: type.eventSource,
        docsAnchor: "turn-on-cloudtrail-data-events",
        message:
          `The trail ${trail.Name ?? ""} doesn't deliver ${type.label} ${which}data events, so ${type.label} data access isn't shown.`.replace(
            "trail  ",
            "trail "
          ),
      },
    ];
  });
};
