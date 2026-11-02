import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import miroConnectorPackageJson from "../package.json" with { type: "json" };
import { router as boardRouter } from "./accesses/board/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

const t = newConnectorTRPC();

const installRouter = t.router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter(
  "miro-ai" as const,
  t,
  {
    board: boardRouter(t),
  },
  installRouter,
  newMetadataRouter(t, miroConnectorPackageJson.version ?? "unknown")
);
