import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { newTailscaleRouter } from "./router.ts";
import { awsIdentityToken } from "./tailscale/identity/aws.ts";

// Everything the control plane needs, also served without the handler from
// `./connector`.
export * from "./connector.ts";

// The Lambda: a federated credential trusts the function's own role.
const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(
  newTailscaleRouter({ identityToken: awsIdentityToken }),
  createContext
);
