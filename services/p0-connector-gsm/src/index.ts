import { createLogger, newCloudFunction } from "@p0security/connector";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const GsmConnectorSpec = connectorSpec;
export const GsmConnectorRouter = connectorRouter;

export type GsmConnectorSpec = typeof connectorSpec;
export type GsmConnectorRouter = typeof connectorRouter;
