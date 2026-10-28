import { createLogger, newCloudFunction } from "@p0security/connector";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export { type InstallValidation as MySqlInstallValidation } from "./install/definition.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const MySqlConnectorSpec = connectorSpec;
export const MySqlConnectorRouter = connectorRouter;

export type MySqlConnectorSpec = typeof connectorSpec;
export type MySqlConnectorRouter = typeof connectorRouter;
