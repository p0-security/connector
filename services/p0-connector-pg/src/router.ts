import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import pgConnectorPackageJson from "../package.json" with { type: "json" };
import { router as roleRouter } from "./accesses/role/handler.ts";
import { router as sqlRouter } from "./accesses/sql/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

const installRouter = router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter(
  "pg" as const,
  t,
  { role: roleRouter(t), sql: sqlRouter(t) },
  installRouter,
  newMetadataRouter(t, pgConnectorPackageJson.version ?? "unknown")
);
