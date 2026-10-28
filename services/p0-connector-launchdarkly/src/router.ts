import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import launchDarklyConnectorPackageJson from "../package.json" with { type: "json" };
import { router as baseRoleRouter } from "./accesses/base-role/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

const t = newConnectorTRPC();

const installRouter = t.router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter(
  "launchdarkly" as const,
  t,
  {
    "base-role": baseRoleRouter(t),
  },
  installRouter,
  newMetadataRouter(t, launchDarklyConnectorPackageJson.version ?? "unknown")
);
