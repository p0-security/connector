import { createLogger, runCloudRunConnector } from "@p0security/connector";

import { connectorRouter } from "./router.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
runCloudRunConnector(
  "P0 Google Drive (Agentic) connector",
  connectorRouter,
  createContext
);
