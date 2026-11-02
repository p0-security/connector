import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import miroConnectorPackageJson from "../package.json" with { type: "json" };
import { router as validationRouter } from "./install/handler.ts";

const t = newConnectorTRPC();

const installRouter = t.router({ validation: validationRouter(t) });

// The board access joins `accesses` with its grant, revoke and listing
// (INT-1110).
export const connectorRouter = newConnectorRouter(
  "miro-ai" as const,
  t,
  {},
  installRouter,
  newMetadataRouter(t, miroConnectorPackageJson.version ?? "unknown")
);
