import {
  ConnectorError,
  type LogQuery,
  type LogSourceHandlers,
} from "@p0security/connector-core";

import { type AwsDependencies, newAws } from "../aws.ts";
import { checkCloudTrail, readCloudTrail } from "./cloudtrail.ts";
import { readRds } from "./rds.ts";

const unsupported = (query: LogQuery) =>
  new ConnectorError({
    type: "validation_error",
    message: `The aws-cloudwatch connector doesn't read ${query.source} logs`,
    payload: { source: query.source },
  });

/** The `logs` route: CloudTrail, and RDS database audit logs. */
export const newLogHandlers = (
  dependencies: AwsDependencies = {}
): LogSourceHandlers => ({
  read: async ({ query, cursor, logGroupName }) => {
    const aws = newAws(dependencies);
    switch (query.source) {
      case "cloudtrail":
        return readCloudTrail(aws, query, logGroupName, cursor);
      case "rds":
        return readRds(aws, query, cursor);
      default:
        throw unsupported(query);
    }
  },
  check: async ({ target, logGroupName }, ctx) => {
    const aws = newAws(dependencies);
    switch (target.source) {
      case "cloudtrail":
        return {
          gaps: await checkCloudTrail(aws, target, logGroupName, ctx.logger),
        };
      // P0 doesn't check whether database auditing is on (spec §14).
      case "rds":
        return { gaps: [] };
      default:
        throw unsupported(target);
    }
  },
});
