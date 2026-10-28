import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import githubConnectorPackageJson from "../package.json" with { type: "json" };
import { router as forceMergeRouter } from "./accesses/force-merge/handler.ts";
import { router as roleRouter } from "./accesses/role/handler.ts";
import { router as teamRouter } from "./accesses/team/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

const installRouter = router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter(
  "github" as const,
  t,
  {
    role: roleRouter(t),
    team: teamRouter(t),
    "force-merge": forceMergeRouter(t),
  },
  installRouter,
  newMetadataRouter(t, githubConnectorPackageJson.version ?? "unknown")
);
