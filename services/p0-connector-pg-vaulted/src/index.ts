import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const PgVaultedConnectorSpec = connectorSpec;
export const PgVaultedConnectorRouter = connectorRouter;

export type PgVaultedConnectorSpec = typeof connectorSpec;
export type PgVaultedConnectorRouter = typeof connectorRouter;
