import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import clickhouseConnectorPackageJson from "../package.json" with { type: "json" };
import { router as consoleRouter } from "./accesses/console/handler.ts";
import { router as sqlRouter } from "./accesses/sql/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();

const installRouter = t.router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter(
  "clickhouse" as const,
  t,
  { sql: sqlRouter(t), console: consoleRouter(t) },
  installRouter,
  newMetadataRouter(t, clickhouseConnectorPackageJson.version ?? "unknown")
);
