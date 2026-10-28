import { createLogger, newCloudFunction } from "@p0security/connector";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const ServiceNowAiConnectorSpec = connectorSpec;
export const ServiceNowAiConnectorRouter = connectorRouter;

export type ServiceNowAiConnectorSpec = typeof connectorSpec;
export type ServiceNowAiConnectorRouter = typeof connectorRouter;
