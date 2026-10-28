import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const DatadogAiConnectorSpec = connectorSpec;
export const DatadogAiConnectorRouter = connectorRouter;

export type DatadogAiConnectorSpec = typeof connectorSpec;
export type DatadogAiConnectorRouter = typeof connectorRouter;
