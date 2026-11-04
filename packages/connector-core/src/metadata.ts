import connectorCorePackageJson from "../package.json" with { type: "json" };
import { audienceCheckFromContext } from "./audience-check.ts";
import type { AnyConnectorTRPCInstance } from "./security-perimeters/common/trpc.ts";

const makeConnectorMetadata = (params: {
  connectorVersion: string;
  frameworkVersion: string;
  audienceCheck: boolean | undefined;
}) => ({
  gitRef: process.env.GIT_REF ?? "unknown",
  buildDate: process.env.BUILD_DATE ?? "unknown",
  workspace: process.env.WORKSPACE ?? "unknown",
  frameworkVersion: params.frameworkVersion ?? "unknown",
  connectorVersion: params.connectorVersion ?? "unknown",
  // Only runHttpConnector reports the field. The other runtimes leave it out.
  ...(params.audienceCheck === undefined
    ? {}
    : { audienceCheck: params.audienceCheck }),
});

/**
 * Builds the `metadata` router P0 reads a connector's build and version from.
 *
 * Served by `runHttpConnector`, `get` also reports `audienceCheck: true`, since
 * that runner compares the token's `aud` to `CONNECTOR_AUDIENCE`. The other
 * runtimes don't report the field.
 */
export const newMetadataRouter = (
  t: AnyConnectorTRPCInstance,
  connectorVersion: string,
  frameworkVersion: string = connectorCorePackageJson.version
) => {
  const { router, procedure } = t;

  return router({
    get: procedure.query(({ ctx }) =>
      makeConnectorMetadata({
        connectorVersion,
        frameworkVersion,
        audienceCheck: audienceCheckFromContext(ctx),
      })
    ),
  });
};
