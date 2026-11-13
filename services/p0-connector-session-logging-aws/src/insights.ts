import {
  DescribeLogGroupsCommand,
  GetQueryResultsCommand,
  StartQueryCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import { ConnectorError } from "@p0security/connector-core";

import { type Aws, isNotFound, toConnectorError } from "./aws.ts";

/** Logs Insights returns at most this many rows per query. */
export const INSIGHTS_ROW_LIMIT = 10_000;

export type LogGroup = { arn?: string; retentionInDays?: number };

/** The named log group, or undefined when it doesn't exist. */
export const describeLogGroup = async (
  aws: Aws,
  logGroupName: string
): Promise<LogGroup | undefined> => {
  const { logGroups = [] } = await aws.logs
    .send(new DescribeLogGroupsCommand({ logGroupNamePrefix: logGroupName }))
    .catch((error: unknown) => {
      throw toConnectorError(error);
    });
  const group = logGroups.find((g) => g.logGroupName === logGroupName);
  return group && { arn: group.arn, retentionInDays: group.retentionInDays };
};

/** Starts a Logs Insights query over `[startMs, endMs)`, to the second. */
export const startQuery = async (
  aws: Aws,
  logGroupName: string,
  queryString: string,
  startMs: number,
  endMs: number
) => {
  const { queryId } = await aws.logs
    .send(
      new StartQueryCommand({
        logGroupName,
        queryString,
        startTime: Math.floor(startMs / 1000),
        endTime: Math.ceil(endMs / 1000),
      })
    )
    .catch((error: unknown) => {
      if (isNotFound(error)) {
        throw new ConnectorError({
          type: "object_not_found",
          message: `The log group ${logGroupName} doesn't exist`,
          payload: { logGroupName },
          cause: error,
        });
      }
      throw toConnectorError(error);
    });
  if (!queryId) {
    throw new ConnectorError({
      type: "unknown",
      message: "Logs Insights returned no query ID",
      payload: {},
    });
  }
  return queryId;
};

export type QueryResults =
  | { status: "complete"; rows: Record<string, string>[] }
  | { status: "running" };

/**
 * One poll of a query. A failed, cancelled or timed-out query is an error:
 * its results would be incomplete.
 */
export const getQueryResults = async (
  aws: Aws,
  queryId: string
): Promise<QueryResults> => {
  const { status, results = [] } = await aws.logs
    .send(new GetQueryResultsCommand({ queryId }))
    .catch((error: unknown) => {
      throw toConnectorError(error);
    });
  switch (status) {
    case "Complete":
      return {
        status: "complete",
        rows: results.map((row) =>
          Object.fromEntries(
            row
              .filter((f) => f.field !== undefined && f.value !== undefined)
              .map((f) => [f.field!, f.value!])
          )
        ),
      };
    case "Scheduled":
    case "Running":
    case "Unknown":
    case undefined:
      return { status: "running" };
    default:
      throw new ConnectorError({
        type: "upstream_unavailable",
        message: `The Logs Insights query ended with status ${status}`,
        payload: { status },
      });
  }
};

const POLL_INTERVALS_MS = [250, 500, 1000, 2000];

/**
 * Polls a query until it completes, or until `deadline` (epoch ms), when it
 * returns `running`.
 */
export const pollQuery = async (
  aws: Aws,
  queryId: string,
  deadline: number
): Promise<QueryResults> => {
  for (let attempt = 0; ; attempt++) {
    const results = await getQueryResults(aws, queryId);
    if (results.status === "complete") return results;
    const interval =
      POLL_INTERVALS_MS[Math.min(attempt, POLL_INTERVALS_MS.length - 1)]!;
    if (aws.now() + interval > deadline) return results;
    await aws.wait(interval);
  }
};

/**
 * A Logs Insights timestamp: `2026-11-01 10:15:00.000` in UTC, or epoch
 * milliseconds from an aggregate such as `max(@timestamp)`.
 */
export const parseInsightsTime = (value: string | undefined) => {
  if (value === undefined || value === "") return undefined;
  if (/^\d+(\.\d+)?$/.test(value)) return Number(value);
  const ms = Date.parse(
    /[zZ]|[+-]\d\d:?\d\d$/.test(value)
      ? value.replace(" ", "T")
      : `${value.replace(" ", "T")}Z`
  );
  return Number.isNaN(ms) ? undefined : ms;
};
