import { createLogger, newCloudFunction } from "@p0security/connector";

import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export { type InstallValidation as GitHubRepositoriesInstallValidation } from "./install/definition.ts";

const logger = createLogger();
const createContext = async () => ({ logger });
export const handler = newCloudFunction(connectorRouter, createContext);

export const GitHubRepositoriesConnectorSpec = connectorSpec;
export const GitHubRepositoriesConnectorRouter = connectorRouter;

export type GitHubRepositoriesConnectorSpec = typeof connectorSpec;
export type GitHubRepositoriesConnectorRouter = typeof connectorRouter;
