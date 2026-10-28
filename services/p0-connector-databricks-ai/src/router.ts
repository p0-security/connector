import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import { router as dataRouter } from "./accesses/data/handler.ts";
import { CONNECTOR_VERSION } from "./databricks/api.ts";
import { router as validationRouter } from "./install/handler.ts";
import { router as principalRouter } from "./install/principal.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

const installRouter = router({
  validation: validationRouter(t),
  principal: principalRouter(t),
});

export const connectorRouter = newConnectorRouter(
  "databricks-ai" as const,
  t,
  { data: dataRouter(t) },
  installRouter,
  newMetadataRouter(t, CONNECTOR_VERSION)
);
