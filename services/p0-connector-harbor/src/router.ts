import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector";

import harborConnectorPackageJson from "../package.json" with { type: "json" };
import { router as projectRoleRouter } from "./accesses/project-role/handler.ts";
import { router as systemAdminRouter } from "./accesses/system-admin/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

const t = newConnectorTRPC();

const installRouter = t.router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter(
  "harbor" as const,
  t,
  { projectRole: projectRoleRouter(t), systemAdmin: systemAdminRouter(t) },
  installRouter,
  newMetadataRouter(t, harborConnectorPackageJson.version ?? "unknown")
);
