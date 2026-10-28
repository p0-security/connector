import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const MongodbAtlasAiConnectorSpec = connectorSpec;
export const MongodbAtlasAiConnectorRouter = connectorRouter;

export type MongodbAtlasAiConnectorSpec = typeof connectorSpec;
export type MongodbAtlasAiConnectorRouter = typeof connectorRouter;
