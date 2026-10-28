import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const GoogleDriveAiConnectorSpec = connectorSpec;
export const GoogleDriveAiConnectorRouter = connectorRouter;

export type GoogleDriveAiConnectorSpec = typeof connectorSpec;
export type GoogleDriveAiConnectorRouter = typeof connectorRouter;
