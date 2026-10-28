import { createLogger, newCloudFunction } from "@p0security/connector";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const TableauAiConnectorSpec = connectorSpec;
export const TableauAiConnectorRouter = connectorRouter;

export type TableauAiConnectorSpec = typeof connectorSpec;
export type TableauAiConnectorRouter = typeof connectorRouter;
