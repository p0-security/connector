import {
  ConnectorError,
  type LogQuery,
  type LogSourceHandlers,
} from "@p0security/connector-core";

import { type AwsDependencies, newAws } from "../aws.ts";
import { checkCloudTrail, readCloudTrail } from "./cloudtrail.ts";

const unsupported = (query: LogQuery) =>
  new ConnectorError({
    type: "validation_error",
    message: `The aws-cloudwatch connector doesn't read ${query.source} logs`,
    payload: { source: query.source },
  });

/** The `logs` route: CloudTrail now; RDS in phase 2. */
export const newLogHandlers = (
  dependencies: AwsDependencies = {}
): LogSourceHandlers => ({
  read: async ({ query, cursor, logGroupName }) => {
    const aws = newAws(dependencies);
    switch (query.source) {
      case "cloudtrail":
        return readCloudTrail(aws, query, logGroupName, cursor);
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
      default:
        throw unsupported(target);
    }
  },
});
