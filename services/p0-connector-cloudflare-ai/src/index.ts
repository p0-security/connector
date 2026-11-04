import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export { account, type Account as CloudflareAiAccount } from "./account.ts";
export {
  installValidation,
  type InstallValidation as CloudflareAiInstallValidation,
} from "./install/definition.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const CloudflareAiConnectorSpec = connectorSpec;
export const CloudflareAiConnectorRouter = connectorRouter;

export type CloudflareAiConnectorSpec = typeof connectorSpec;
export type CloudflareAiConnectorRouter = typeof connectorRouter;
