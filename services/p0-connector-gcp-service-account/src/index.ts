import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const GcpServiceAccountConnectorSpec = connectorSpec;
export const GcpServiceAccountConnectorRouter = connectorRouter;

export type GcpServiceAccountConnectorSpec = typeof connectorSpec;
export type GcpServiceAccountConnectorRouter = typeof connectorRouter;
