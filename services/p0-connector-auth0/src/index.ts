import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { requireAllowedDomains } from "./allowed-domains.ts";
import { connectorRouter } from "./router.ts";

// Without a usable `DOMAIN_ALLOW_PATTERN` the connector refuses to start,
// and says which variable is wrong.
requireAllowedDomains();

const logger = createLogger();
export const handler = newCloudFunction(connectorRouter, async () => ({
  logger,
}));
