import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import packageJson from "../package.json" with { type: "json" };
import { router as roleRouter } from "./accesses/role/handler.ts";
import { router as installRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();

export const connectorRouter = newConnectorRouter(
  "pingone-aws-iam-federation" as const,
  t,
  {
    accesses: { role: roleRouter(t) },
    install: installRouter(t),
    metadata: newMetadataRouter(t, packageJson.version ?? "unknown"),
  }
);
