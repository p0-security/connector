import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const SalesforceAiConnectorSpec = connectorSpec;
export const SalesforceAiConnectorRouter = connectorRouter;

export type SalesforceAiConnectorSpec = typeof connectorSpec;
export type SalesforceAiConnectorRouter = typeof connectorRouter;
