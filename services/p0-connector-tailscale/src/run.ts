import { createLogger, runCloudRunConnector } from "@p0security/connector-core";

import { newTailscaleRouter } from "./router.ts";
import { gcpIdentityToken } from "./tailscale/identity/gcp.ts";

// The Cloud Run runner accepts a call only when its ID token's `email` claim
// is `INVOKER_SA_EMAIL`, P0's service account. A federated credential trusts
// the service's own account, through the metadata server.
const logger = createLogger();
const createContext = async () => ({ logger });
runCloudRunConnector(
  "P0 Tailscale connector",
  newTailscaleRouter({ identityToken: gcpIdentityToken }),
  createContext
);
