import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import redshiftAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as objectsRouter } from "./accesses/objects/handler.ts";
import { router as roleRouter } from "./accesses/role/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

const installRouter = router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter("redshift-ai" as const, t, {
  accesses: { role: roleRouter(t), objects: objectsRouter(t) },
  install: installRouter,
  metadata: newMetadataRouter(
    t,
    redshiftAiConnectorPackageJson.version ?? "unknown"
  ),
});
