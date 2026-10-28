import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector";

import { router as adminRouter } from "./accesses/admin/handler.ts";
import { router as privilegeRouter } from "./accesses/privilege/handler.ts";
import { CONNECTOR_VERSION } from "./databricks/api.ts";
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

const installRouter = router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter(
  "databricks" as const,
  t,
  { privilege: privilegeRouter(t), admin: adminRouter(t) },
  installRouter,
  newMetadataRouter(t, CONNECTOR_VERSION)
);
