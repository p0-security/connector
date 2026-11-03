import { createLogger, runCloudRunConnector } from "@p0security/connector-core";

import { requireAllowedDomains } from "./allowed-domains.ts";
import { connectorRouter } from "./router.ts";

// Checked before the server starts.
requireAllowedDomains();

const logger = createLogger();
runCloudRunConnector("P0 1Password connector", connectorRouter, async () => ({
  logger,
}));
