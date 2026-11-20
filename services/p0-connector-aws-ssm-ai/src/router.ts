import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import awsSsmAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as sessionAccessRouter } from "./accesses/session/handler.ts";
import { router as validationRouter } from "./install/handler.ts";
import { router as endSessionsRouter } from "./sessions/handler.ts";

export const t = newConnectorTRPC();

// The sessions route sits here: the connector router has no other slot for
// a route of the integration's own.
const installRouter = t.router({
  validation: validationRouter(t),
  sessions: endSessionsRouter(t),
});

export const connectorRouter = newConnectorRouter("aws-ssm-ai" as const, t, {
  accesses: { session: sessionAccessRouter(t) },
  install: installRouter,
  metadata: newMetadataRouter(
    t,
    awsSsmAiConnectorPackageJson.version ?? "unknown"
  ),
});
