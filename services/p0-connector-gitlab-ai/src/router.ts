import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import gitlabAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as permissionRouter } from "./accesses/permission/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

const installRouter = router({});

export const connectorRouter = newConnectorRouter(
  "gitlab-ai" as const,
  t,
  { permission: permissionRouter(t) },
  installRouter,
  newMetadataRouter(t, gitlabAiConnectorPackageJson.version ?? "unknown")
);
