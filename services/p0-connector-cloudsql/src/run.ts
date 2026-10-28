import { createLogger, runCloudRunConnector } from "@p0security/connector-core";
import { MySqlConnectorRouter } from "@p0security/p0-connector-mysql";
import { PostgresConnectorRouter } from "@p0security/p0-connector-pg";

import { connectorRouter, t } from "./router.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
runCloudRunConnector(
  "P0 CloudSQL connector",
  t.mergeRouters(
    connectorRouter,
    PostgresConnectorRouter,
    MySqlConnectorRouter
  ),
  createContext
);
