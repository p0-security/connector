import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector";

import serviceNowAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as roleRouter } from "./accesses/role/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

const installRouter = router({});

export const connectorRouter = newConnectorRouter(
  "servicenow-ai" as const,
  t,
  { role: roleRouter(t) },
  installRouter,
  newMetadataRouter(t, serviceNowAiConnectorPackageJson.version ?? "unknown")
);
