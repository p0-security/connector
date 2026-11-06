import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const GitguardianAiConnectorSpec = connectorSpec;
export const GitguardianAiConnectorRouter = connectorRouter;

export type GitguardianAiConnectorSpec = typeof connectorSpec;
export type GitguardianAiConnectorRouter = typeof connectorRouter;
