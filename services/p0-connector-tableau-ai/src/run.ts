import { createLogger, runCloudRunConnector } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
runCloudRunConnector(
  "P0 Tableau (Agentic) connector",
  connectorRouter,
  createContext
);
