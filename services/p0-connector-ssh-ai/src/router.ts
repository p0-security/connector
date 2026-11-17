import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import sshAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as sessionAccessRouter } from "./accesses/session/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();

const installRouter = t.router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter("ssh-ai" as const, t, {
  accesses: { session: sessionAccessRouter(t) },
  install: installRouter,
  metadata: newMetadataRouter(
    t,
    sshAiConnectorPackageJson.version ?? "unknown"
  ),
});
