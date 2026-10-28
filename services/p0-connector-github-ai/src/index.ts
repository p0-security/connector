import { createLogger, newCloudFunction } from "@p0security/connector";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const GitHubAiConnectorSpec = connectorSpec;
export const GitHubAiConnectorRouter = connectorRouter;

export type GitHubAiConnectorSpec = typeof connectorSpec;
export type GitHubAiConnectorRouter = typeof connectorRouter;
