import connectorCorePackageJson from "../package.json" with { type: "json" };
import type { AnyConnectorTRPCInstance } from "./securityPerimeters/common/trpc.ts";

const makeConnectorMetadata = (params: {
  connectorVersion: string;
  frameworkVersion: string;
}) => ({
  gitRef: process.env.GIT_REF ?? "unknown",
  buildDate: process.env.BUILD_DATE ?? "unknown",
  workspace: process.env.WORKSPACE ?? "unknown",
  frameworkVersion: params.frameworkVersion ?? "unknown",
  connectorVersion: params.connectorVersion ?? "unknown",
});

export const newMetadataRouter = (
  t: AnyConnectorTRPCInstance,
  connectorVersion: string,
  frameworkVersion: string = connectorCorePackageJson.version
) => {
  const { router, procedure } = t;

  return router({
    get: procedure.query(() =>
      makeConnectorMetadata({ connectorVersion, frameworkVersion })
    ),
  });
};
