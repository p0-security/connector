import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import sshAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();

const installRouter = t.router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter("ssh-ai" as const, t, {
  // Empty until the grant and revoke routes land.
  accesses: {},
  install: installRouter,
  metadata: newMetadataRouter(
    t,
    sshAiConnectorPackageJson.version ?? "unknown"
  ),
});
