import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

export { app, type App as OktaAwsIamFederationApp } from "./account.ts";
export {
  installValidation,
  type InstallValidation as OktaAwsIamFederationInstallValidation,
} from "./install/definition.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const OktaAwsIamFederationConnectorRouter = connectorRouter;

export type OktaAwsIamFederationConnectorRouter = typeof connectorRouter;
