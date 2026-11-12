import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import argocdConnectorPackageJson from "../package.json" with { type: "json" };
import { router as globalRoleRouter } from "./accesses/global-role/handler.ts";
import { router as projectRoleRouter } from "./accesses/project-role/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

const t = newConnectorTRPC();

const installRouter = t.router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter("argocd" as const, t, {
  accesses: {
    globalRole: globalRoleRouter(t),
    projectRole: projectRoleRouter(t),
  },
  install: installRouter,
  metadata: newMetadataRouter(
    t,
    argocdConnectorPackageJson.version ?? "unknown"
  ),
});
