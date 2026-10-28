import { createLogger, newCloudFunction } from "@p0security/connector";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const SnowflakeAiConnectorSpec = connectorSpec;
export const SnowflakeAiConnectorRouter = connectorRouter;

export type SnowflakeAiConnectorSpec = typeof connectorSpec;
export type SnowflakeAiConnectorRouter = typeof connectorRouter;
