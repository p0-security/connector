import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

export { app, type App as PingFederateAwsIamFederationApp } from "./account.ts";
export {
  installValidation,
  type InstallValidation as PingFederateAwsIamFederationInstallValidation,
} from "./install/definition.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const PingFederateAwsIamFederationConnectorRouter = connectorRouter;

export type PingFederateAwsIamFederationConnectorRouter =
  typeof connectorRouter;
