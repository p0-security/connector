// copy of services/p0-connector-harbor/src/run.ts
import { createLogger, runCloudRunConnector } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

// The Cloud Run runner accepts a call only when its ID token's `email` claim
// is `INVOKER_SA_EMAIL`, P0's service account. It checks the token's audience
// only when `INVOKER_AUDIENCE` is set; otherwise Cloud Run's own invoker check
// is what turns away a token minted for another service that trusts the same
// account, so the service has to stay private.
const logger = createLogger();
const createContext = async () => ({ logger });
runCloudRunConnector("P0 Argo CD connector", connectorRouter, createContext);
