import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import gitguardianAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

// The `permission` access is added with its handler.
const installRouter = router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter(
  "gitguardian-ai" as const,
  t,
  {},
  installRouter,
  newMetadataRouter(t, gitguardianAiConnectorPackageJson.version ?? "unknown")
);
