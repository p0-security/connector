import {
  newConnectorRouter,
  newConnectorTRPC,
  newLogsRouter,
  newMetadataRouter,
} from "@p0security/connector-core";

import awsCloudWatchConnectorPackageJson from "../package.json" with { type: "json" };
import type { AwsDependencies } from "./aws.ts";
import { router as validationRouter } from "./install/handler.ts";
import { newLogHandlers } from "./logs/handlers.ts";

export const NAMESPACE = "aws-cloudwatch" as const;

/** The connector's router; `dependencies` stand in for AWS in tests. */
export const newAwsCloudWatchRouter = (dependencies: AwsDependencies = {}) => {
  const t = newConnectorTRPC();
  return newConnectorRouter(
    NAMESPACE,
    t,
    {},
    t.router({ validation: validationRouter(t, dependencies) }),
    newMetadataRouter(
      t,
      awsCloudWatchConnectorPackageJson.version ?? "unknown"
    ),
    newLogsRouter(t, newLogHandlers(dependencies))
  );
};

export const connectorRouter = newAwsCloudWatchRouter();
