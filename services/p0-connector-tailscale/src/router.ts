import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import tailscaleConnectorPackageJson from "../package.json" with { type: "json" };
import { router as postureRouter } from "./accesses/posture/handler.ts";
import type { ConnectorDeps } from "./deps.ts";
import { router as destinationRouter } from "./destinations/check.ts";
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();

/**
 * The connector's router. Each entry point builds it with its cloud's
 * identity token source; the control plane only ever sees its type.
 */
export const newTailscaleRouter = (deps: ConnectorDeps) => {
  // The integration's own routes sit here: the connector router has no other
  // slot for them.
  const installRouter = t.router({
    validation: validationRouter(t, deps),
    destination: destinationRouter(t, deps),
  });

  return newConnectorRouter(
    "tailscale" as const,
    t,
    { posture: postureRouter(t, deps) },
    installRouter,
    newMetadataRouter(t, tailscaleConnectorPackageJson.version ?? "unknown")
  );
};
