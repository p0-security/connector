import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import dockerConnectorPackageJson from "../package.json" with { type: "json" };
import { router as roleRouter } from "./accesses/role/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();

const installRouter = t.router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter(
  "docker" as const,
  t,
  { role: roleRouter(t) },
  installRouter,
  newMetadataRouter(t, dockerConnectorPackageJson.version ?? "unknown")
);
