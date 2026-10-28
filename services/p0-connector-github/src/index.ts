import { createLogger, newCloudFunction } from "@p0security/connector-core";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export { type InstallValidation as GitHubInstallValidation } from "./install/definition.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const GitHubConnectorSpec = connectorSpec;
export const GitHubConnectorRouter = connectorRouter;

export type GitHubConnectorSpec = typeof connectorSpec;
export type GitHubConnectorRouter = typeof connectorRouter;
