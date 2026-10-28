import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import lookerAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as modelRouter } from "./accesses/model/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

const installRouter = router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter(
  "looker-ai" as const,
  t,
  { model: modelRouter(t) },
  installRouter,
  newMetadataRouter(t, lookerAiConnectorPackageJson.version ?? "unknown")
);
