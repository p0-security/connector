import { createLogger, newCloudFunction } from "@p0security/connector";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const PagerdutyAiConnectorSpec = connectorSpec;
export const PagerdutyAiConnectorRouter = connectorRouter;

export type PagerdutyAiConnectorSpec = typeof connectorSpec;
export type PagerdutyAiConnectorRouter = typeof connectorRouter;
