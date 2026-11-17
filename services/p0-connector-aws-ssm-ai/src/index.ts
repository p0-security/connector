import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

export {
  installContext,
  requestContext,
  type InstallContext as AwsSsmAiInstallContext,
  type RequestContext as AwsSsmAiRequestContext,
} from "./context.ts";
export {
  AWS_SSM_AI_INSTALL_STEPS,
  type InstallValidation as AwsSsmAiInstallValidation,
  type AwsSsmAiInstallStep,
} from "./install/definition.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const AwsSsmAiConnectorRouter = connectorRouter;

export type AwsSsmAiConnectorRouter = typeof connectorRouter;
