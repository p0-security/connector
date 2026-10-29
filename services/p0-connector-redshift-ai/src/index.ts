import { createLogger, newCloudFunction } from "@p0security/connector";

import { connectorRouter } from "./router.ts";

// Everything the control plane needs, also served without the handler from
// `./connector`.
export * from "./connector.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const RedshiftAiConnectorRouter = connectorRouter;
export type RedshiftAiConnectorRouter = typeof connectorRouter;
