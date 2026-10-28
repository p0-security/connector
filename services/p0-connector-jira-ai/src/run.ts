import { createLogger, runCloudRunConnector } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

// The Cloud Run runner accepts a call only when its ID token's `email` claim
// is `INVOKER_SA_EMAIL`, P0's service account, and its `aud` claim is
// `CONNECTOR_AUDIENCE`, so both variables are required.
const logger = createLogger();
const createContext = async () => ({ logger });
runCloudRunConnector("P0 Jira (AI) connector", connectorRouter, createContext);
