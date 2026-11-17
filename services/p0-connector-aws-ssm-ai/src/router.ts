import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import awsSsmAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();

const installRouter = t.router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter("aws-ssm-ai" as const, t, {
  // Empty until the grant and revoke routes land.
  accesses: {},
  install: installRouter,
  metadata: newMetadataRouter(
    t,
    awsSsmAiConnectorPackageJson.version ?? "unknown"
  ),
});
