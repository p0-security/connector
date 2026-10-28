import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const GitlabAiConnectorSpec = connectorSpec;
export const GitlabAiConnectorRouter = connectorRouter;

export type GitlabAiConnectorSpec = typeof connectorSpec;
export type GitlabAiConnectorRouter = typeof connectorRouter;
