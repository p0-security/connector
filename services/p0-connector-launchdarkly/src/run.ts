import { createLogger, runCloudRunConnector } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

// The Cloud Run runner accepts a call only when its ID token's `email` claim
// is `INVOKER_SA_EMAIL`, P0's service account, and, when `CONNECTOR_AUDIENCE`
// is set, its `aud` claim is exactly that. The Cloud Run image sets
// `CONNECTOR_AUDIENCE_CHECK=cloud-run-iam`, so without `CONNECTOR_AUDIENCE`
// Cloud Run's own invoker check is what turns away a token minted for another
// service that trusts the same account, and the service has to stay private.
const logger = createLogger();
const createContext = async () => ({ logger });
runCloudRunConnector(
  "P0 LaunchDarkly connector",
  connectorRouter,
  createContext
);
