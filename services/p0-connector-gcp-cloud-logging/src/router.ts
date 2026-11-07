import {
  newConnectorRouter,
  newConnectorTRPC,
  newLogsRouter,
  newMetadataRouter,
} from "@p0security/connector-core";

import gcpCloudLoggingConnectorPackageJson from "../package.json" with { type: "json" };
import { router as validationRouter } from "./install/handler.ts";
import type { LoggingDependencies } from "./logging.ts";
import { newLogHandlers } from "./logs/handlers.ts";

export const NAMESPACE = "gcp-cloud-logging" as const;

/** The connector's router; `dependencies` stand in for Cloud Logging in tests. */
export const newGcpCloudLoggingRouter = (
  dependencies: LoggingDependencies = {}
) => {
  const t = newConnectorTRPC();
  return newConnectorRouter(
    NAMESPACE,
    t,
    {},
    t.router({ validation: validationRouter(t, dependencies) }),
    newMetadataRouter(
      t,
      gcpCloudLoggingConnectorPackageJson.version ?? "unknown"
    ),
    newLogsRouter(t, newLogHandlers(dependencies))
  );
};

export const connectorRouter = newGcpCloudLoggingRouter();
