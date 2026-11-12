import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import salesforceAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as permissionSetRouter } from "./accesses/permission-set/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

const installRouter = router({});

export const connectorRouter = newConnectorRouter("salesforce-ai" as const, t, {
  accesses: { "permission-set": permissionSetRouter(t) },
  install: installRouter,
  metadata: newMetadataRouter(
    t,
    salesforceAiConnectorPackageJson.version ?? "unknown"
  ),
});
