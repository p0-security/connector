import { createLogger, newCloudFunction } from "@p0security/connector";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export { type InstallValidation as PostgresInstallValidation } from "./install/definition.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const PostgresConnectorSpec = connectorSpec;
export const PostgresConnectorRouter = connectorRouter;

export type PostgresConnectorSpec = typeof connectorSpec;
export type PostgresConnectorRouter = typeof connectorRouter;
