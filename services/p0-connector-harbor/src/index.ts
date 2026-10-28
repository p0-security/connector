import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

// Everything the control plane needs, also served without the handler from
// `./connector`.
export * from "./connector.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);
