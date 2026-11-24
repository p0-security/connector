import type {
  CloudTrailIdentity,
  CloudTrailLogQuery,
} from "@p0security/connector-core";

import { INSIGHTS_ROW_LIMIT } from "../insights.ts";
import {
  assertQuerySafe,
  escapeRegex,
  globSource,
  insightsString,
} from "../patterns.ts";
import { pushdownEventSources } from "./services.ts";

/** Any AWS partition: `aws`, `aws-us-gov`, `aws-cn`. */
const PARTITION = "aws[a-z-]*";

/**
 * The pattern a role session's `userIdentity.arn` must match, as regex
 * source without delimiters, or undefined when the identity isn't a role
 * session matched on its ARN. Role and session names are matched
 * case-insensitively, as IAM treats role names.
 */
export const sessionArnSource = (
  accountId: string,
  identity: CloudTrailIdentity
) => {
  const prefix = `^arn:${PARTITION}:sts::${escapeRegex(accountId)}:assumed-role\\/`;
  switch (identity.kind) {
    case "assumed-role": {
      const role =
        identity.roleName !== undefined
          ? escapeRegex(assertQuerySafe(identity.roleName))
          : globSource(assertQuerySafe(identity.roleNamePattern!), "[^/]*");
      const session =
        identity.sessionName !== undefined
          ? escapeRegex(assertQuerySafe(identity.sessionName))
          : "[^/]+";
      return `${prefix}${role}\\/${session}$`;
    }
    case "source-identity":
      return identity.roleName === undefined
        ? undefined
        : `${prefix}${escapeRegex(assertQuerySafe(identity.roleName))}\\/[^/]+$`;
    case "iam-user":
      return undefined;
  }
};

/**
 * The user name in an `iam-user` identity's `userArn`: its last segment.
 * The ARN P0 sends may leave out the user's IAM path, which the grant doesn't
 * store, so an IAM user is matched on its name and account, which identify
 * it whatever its path, rather than on its ARN.
 */
export const iamUserName = (userArn: string) =>
  userArn.slice(userArn.lastIndexOf("/") + 1);

const identityFilters = (query: CloudTrailLogQuery) => {
  const { identity, accountId } = query;
  const filters: string[] = [];
  const arnSource = sessionArnSource(accountId, identity);
  if (arnSource !== undefined) {
    filters.push(`userIdentity.arn =~ /(?i)${arnSource}/`);
  }
  if (identity.kind === "source-identity") {
    filters.push(
      `userIdentity.sessionContext.sourceIdentity = ${insightsString(identity.value)}`
    );
  }
  if (identity.kind === "iam-user") {
    filters.push(
      `userIdentity.type = "IAMUser"`,
      `userIdentity.accountId = ${insightsString(accountId)}`,
      `userIdentity.userName = ${insightsString(iamUserName(identity.userArn))}`
    );
  }
  return filters;
};

/**
 * The Logs Insights query for a CloudTrail `LogQuery`. Account, identity and
 * service are pushed down; action names and resources aren't, because IAM
 * names and CloudTrail names differ and many events carry no resource ARN,
 * so the connector narrows those itself (see `narrow.ts`). The time range is
 * the query's own `startTime`/`endTime`, not a filter.
 */
export const composeInsightsQuery = (query: CloudTrailLogQuery) => {
  const filters = [
    `recipientAccountId = ${insightsString(query.accountId)}`,
    ...identityFilters(query),
  ];
  const sources = query.actions && pushdownEventSources(query.actions);
  if (sources && sources.length > 0) {
    filters.push(`eventSource in [${sources.map(insightsString).join(", ")}]`);
  }
  return [
    "fields @timestamp, @message",
    ...filters.map((f) => `| filter ${f}`),
    `| limit ${INSIGHTS_ROW_LIMIT}`,
  ].join("\n");
};

/** Every CloudTrail event, by account, for install validation's sample. */
export const RECENT_EVENTS_QUERY = [
  "filter ispresent(eventID) and ispresent(recipientAccountId)",
  "| stats count(*) as events, max(@timestamp) as latest by recipientAccountId",
  "| limit 1000",
].join("\n");
