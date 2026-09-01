import {
  type CloudFunctionOutput,
  type ConnectorContext,
  createLogger,
  newCloudFunction,
  runCloudRunConnector,
} from "@p0security/connector-core";

import { CUSTOM_APP_NAMESPACE } from "./constants.ts";
import {
  type CustomAppConnectorParams,
  newCustomAppConnectorRouter,
} from "./router.ts";

/**
 * The tRPC context every connector procedure runs with.
 */
const newConnectorContext = () => {
  const logger = createLogger({ connector: CUSTOM_APP_NAMESPACE });
  return async (): Promise<ConnectorContext> => ({ logger });
};

/**
 * Builds the AWS Lambda handler for a Custom Application connector:
 *
 * ```ts
 * export const handler = newCustomAppLambdaHandler({
 *   actions,
 *   connectorVersion: packageJson.version,
 * });
 * ```
 *
 * @category Deployment
 */
export const newCustomAppLambdaHandler = (
  params: CustomAppConnectorParams
): ((input: unknown) => Promise<CloudFunctionOutput>) =>
  newCloudFunction(newCustomAppConnectorRouter(params), newConnectorContext());

/**
 * Builds the GCP Cloud Run server for a Custom Application connector:
 *
 * ```ts
 * const run = newCustomAppCloudRunServer({
 *   actions,
 *   connectorVersion: packageJson.version,
 * });
 * run();
 * ```
 * @category Deployment
 */
export const newCustomAppCloudRunServer = (
  params: CustomAppConnectorParams
): (() => void) => {
  const router = newCustomAppConnectorRouter(params);
  const createContext = newConnectorContext();
  return () =>
    runCloudRunConnector(CUSTOM_APP_NAMESPACE, router, createContext);
};
