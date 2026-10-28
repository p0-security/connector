import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector";

import pagerdutyAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as permissionRouter } from "./accesses/permission/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

const installRouter = router({});

export const connectorRouter = newConnectorRouter(
  "pagerduty-ai" as const,
  t,
  { permission: permissionRouter(t) },
  installRouter,
  newMetadataRouter(t, pagerdutyAiConnectorPackageJson.version ?? "unknown")
);
