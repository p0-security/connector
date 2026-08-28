import {
  newMetadataRouter as newCoreMetadataRouter,
  type AnyConnectorTRPCInstance,
} from "@p0security/connector-core";

import sdkPackageJson from "../package.json" with { type: "json" };

export const newMetadataRouter = (
  t: AnyConnectorTRPCInstance,
  connectorVersion: string
) => newCoreMetadataRouter(t, connectorVersion, sdkPackageJson.version);
