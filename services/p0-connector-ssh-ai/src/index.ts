import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";

export {
  installContext,
  requestContext,
  type InstallContext as SshAiInstallContext,
  type RequestContext as SshAiRequestContext,
} from "./context.ts";
export {
  SSH_AI_INSTALL_STEPS,
  type InstallValidation as SshAiInstallValidation,
  type SshAiInstallStep,
} from "./install/definition.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const SshAiConnectorRouter = connectorRouter;

export type SshAiConnectorRouter = typeof connectorRouter;
