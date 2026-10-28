import { requireAllowedDomains } from "./allowed-domains.ts";

// Checked before the server starts, and before anything else loads. See
// TODO(INT-369) in `index.ts` for why the rest is imported dynamically.
requireAllowedDomains();

const { createLogger, runCloudRunConnector } =
  await import("@p0security/connector-core");
const { connectorRouter } = await import("./router.ts");

const logger = createLogger();
runCloudRunConnector("P0 Docker Hub connector", connectorRouter, async () => ({
  logger,
}));
