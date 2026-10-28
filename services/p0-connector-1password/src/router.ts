import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector";

import onePasswordConnectorPackageJson from "../package.json" with { type: "json" };
import { router as shareRouter } from "./accesses/share/handler.ts";
import { router as validationRouter } from "./install/handler.ts";
import { router as shareCreationRouter } from "./share/handler.ts";

export const t = newConnectorTRPC();

// The share route sits here: the connector router has no other slot for a
// route of the integration's own.
const installRouter = t.router({
  validation: validationRouter(t),
  share: shareCreationRouter(t),
});

export const connectorRouter = newConnectorRouter(
  "1password" as const,
  t,
  { share: shareRouter(t) },
  installRouter,
  newMetadataRouter(t, onePasswordConnectorPackageJson.version ?? "unknown")
);
