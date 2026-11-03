import { createLogger, runCloudRunConnector } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

// The Cloud Run runner accepts a call only when its ID token's `email` claim
// is `INVOKER_SA_EMAIL`, P0's service account. It doesn't check the token's
// audience: Cloud Run's own invoker check is what turns away a token minted
// for another service that trusts the same account, so the service has to
// stay private.
const logger = createLogger();
const createContext = async () => ({ logger });
runCloudRunConnector("P0 Harbor connector", connectorRouter, createContext);
