import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector";

import gsmConnectorPackageJson from "../package.json" with { type: "json" };
import { router as secretsRouter } from "./accesses/secrets/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

// Currently no-op; should have it's IAM permissions set by P0 backend prior to running?
const installRouter = router({});

export const connectorRouter = newConnectorRouter(
  "gsm" as const,
  t,
  { secrets: secretsRouter(t) },
  installRouter,
  newMetadataRouter(t, gsmConnectorPackageJson.version ?? "unknown")
);
