import {
  type AnyConnectorTRPCInstance,
  newMetadataRouter as newCoreMetadataRouter,
} from "@p0security/connector-core";

import sdkPackageJson from "../package.json" with { type: "json" };

/**
 * Reports the SDK's own version as both the connector and framework version.
 * A custom application connector is the SDK deployed with the customer's
 * actions, so the SDK version is the version of the deployable.
 */
export const newMetadataRouter = (t: AnyConnectorTRPCInstance) =>
  newCoreMetadataRouter(t, sdkPackageJson.version, sdkPackageJson.version);
