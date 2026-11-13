import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import cloudflareAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as permissionRouter } from "./accesses/permission/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

const installRouter = router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter("cloudflare-ai" as const, t, {
  accesses: { permission: permissionRouter(t) },
  install: installRouter,
  metadata: newMetadataRouter(
    t,
    cloudflareAiConnectorPackageJson.version ?? "unknown"
  ),
});
