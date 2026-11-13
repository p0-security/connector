import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import {
  type Aws,
  type AwsDependencies,
  newAws,
  toConnectorError,
} from "../aws.ts";
import { RECENT_EVENTS_QUERY } from "../cloudtrail/query.ts";
import {
  deliveredDataEventTypes,
  findDeliveringTrail,
  missingDataEventTypes,
} from "../cloudtrail/trail.ts";
import {
  describeLogGroup,
  parseInsightsTime,
  pollQuery,
  startQuery,
} from "../insights.ts";
import {
  type AwsCloudWatchInstallStep,
  type InstallInput,
  type InstallValidation,
  type InstallWarning,
  installInput,
} from "./definition.ts";

const DAY_MS = 86_400_000;

/** How long validation waits for its sample query: inside the Lambda's
 * timeout, and long enough for a day of an organization trail. */
const SAMPLE_DEADLINE_MS = 60_000;

/** Runs `run` as `step`; its failure is thrown carrying the step. */
const at = async <T>(
  step: AwsCloudWatchInstallStep,
  run: () => Promise<T>
): Promise<T> => {
  try {
    return await run();
  } catch (error) {
    const { data } = toConnectorError(error);
    if ("step" in data.payload) throw error;
    throw new ConnectorError({ ...data, payload: { ...data.payload, step } });
  }
};

const failed = (
  step: AwsCloudWatchInstallStep,
  type: ConnectorErrorOptions["type"],
  message: string,
  payload: Record<string, string> = {}
) => new ConnectorError({ type, message, payload: { ...payload, step } });

/** The accounts in the group's last day of events, and the newest event. */
const sampleRecentEvents = async (aws: Aws, logGroupName: string) => {
  const now = aws.now();
  const queryId = await startQuery(
    aws,
    logGroupName,
    RECENT_EVENTS_QUERY,
    now - DAY_MS,
    now
  );
  const results = await pollQuery(aws, queryId, now + SAMPLE_DEADLINE_MS);
  if (results.status !== "complete") {
    throw failed(
      "recent_events",
      "upstream_unavailable",
      "The Logs Insights sample of the last day didn't finish in time"
    );
  }
  const accounts = results.rows
    .filter((row) => Number(row.events ?? 0) > 0 && row.recipientAccountId)
    .map((row) => row.recipientAccountId!)
    .sort();
  const latest = Math.max(
    ...results.rows.map((row) => parseInsightsTime(row.latest) ?? -Infinity)
  );
  return { accounts, latest };
};

/** Every check, in order. */
export const validateInstall = async (
  input: InstallInput,
  logger: Logger,
  dependencies: AwsDependencies = {}
): Promise<InstallValidation> => {
  const { logGroupName, coverage = "account" } = input;
  if (logGroupName === undefined) {
    if (input.coverage !== undefined) {
      throw failed(
        "log_group",
        "validation_error",
        "CloudTrail coverage needs a log group"
      );
    }
    return { warnings: [] };
  }
  const aws = newAws(dependencies);
  const warnings: InstallWarning[] = [];

  const group = await at("log_group", () =>
    describeLogGroup(aws, logGroupName)
  );
  if (!group) {
    throw failed(
      "log_group",
      "object_not_found",
      `The log group ${logGroupName} doesn't exist in this account and region`,
      { logGroupName }
    );
  }

  const { accounts, latest } = await at("recent_events", () =>
    sampleRecentEvents(aws, logGroupName)
  );
  if (accounts.length === 0 || !Number.isFinite(latest)) {
    throw failed(
      "recent_events",
      "object_not_found",
      `The log group ${logGroupName} holds no CloudTrail event from the last 24 hours. Check that a trail delivers to it.`,
      { logGroupName }
    );
  }

  const trail = await at("coverage", () =>
    findDeliveringTrail(aws, logGroupName, group.arn)
  );
  const isOrganizationTrail = trail
    ? trail.IsOrganizationTrail === true
    : accounts.length > 1;
  if (coverage === "organization" && !isOrganizationTrail) {
    throw failed(
      "coverage",
      "validation_error",
      trail
        ? `The trail ${trail.Name} delivering to ${logGroupName} isn't an organization trail, so it can't cover the organization`
        : `The log group ${logGroupName} only holds events from account ${accounts[0]}, so it can't cover the organization`,
      { logGroupName }
    );
  }
  if (coverage === "account" && trail?.IsOrganizationTrail) {
    warnings.push({
      check: "coverage",
      message: `The trail ${trail.Name} is an organization trail; installing this item with organization coverage would cover every account.`,
    });
  }

  let dataEventTypes: string[] = [];
  if (trail) {
    const delivered = await at("data_events", () =>
      deliveredDataEventTypes(aws, trail)
    );
    dataEventTypes = [...delivered.keys()].sort();
    const missing = missingDataEventTypes(delivered);
    if (missing.length > 0) {
      warnings.push({
        check: "data_events",
        resourceTypes: missing.map((t) => t.resourceType),
      });
    }
  } else {
    warnings.push({
      check: "trail_not_found",
      message: `No trail in this account and region delivers to ${logGroupName}, so P0 can't read which data events it delivers.`,
    });
  }

  logger.info(
    { logGroupName, accounts: accounts.length, warnings },
    "validated the CloudWatch Logs install"
  );
  return {
    cloudtrail: {
      logGroupName,
      ...(group.arn ? { logGroupArn: group.arn } : {}),
      ...(group.retentionInDays !== undefined
        ? { retentionInDays: group.retentionInDays }
        : {}),
      latestEventTime: new Date(latest).toISOString(),
      accounts,
      ...(trail?.TrailARN
        ? {
            trail: {
              arn: trail.TrailARN,
              name: trail.Name ?? trail.TrailARN,
              isOrganizationTrail: trail.IsOrganizationTrail === true,
            },
          }
        : {}),
      dataEventTypes,
    },
    warnings,
  };
};

/**
 * Lets the installer confirm the connector can read the item's CloudTrail
 * group. `get` runs on every validation, so it never writes.
 */
export const router = (
  t: AnyConnectorTRPCInstance,
  dependencies: AwsDependencies = {}
) => {
  const procedure = withRouteLogging(t.procedure);
  return t.router({
    get: procedure
      .input(installInput.parse)
      .query(({ input, ctx }): Promise<InstallValidation> =>
        validateInstall(input, ctx.logger, dependencies)
      ),
  });
};
