import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

export { app, type App as PingOneAwsIamFederationApp } from "./account.ts";
export {
  installValidation,
  type InstallValidation as PingOneAwsIamFederationInstallValidation,
} from "./install/definition.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const PingOneAwsIamFederationConnectorRouter = connectorRouter;

export type PingOneAwsIamFederationConnectorRouter = typeof connectorRouter;
