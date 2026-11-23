import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const PgVaultedConnectorRouter = connectorRouter;

export type PgVaultedConnectorRouter = typeof connectorRouter;
