import { createLogger, newCloudFunction } from "@p0security/connector";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const LookerAiConnectorSpec = connectorSpec;
export const LookerAiConnectorRouter = connectorRouter;

export type LookerAiConnectorSpec = typeof connectorSpec;
export type LookerAiConnectorRouter = typeof connectorRouter;
