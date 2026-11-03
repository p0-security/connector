import {
  type CloudFunctionOutput,
  type ConnectorContext,
  createLogger,
  newCloudFunction,
  runCloudRunConnector,
  runHttpConnector,
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
 *
 * With `CONNECTOR_AUDIENCE` set, the server rejects a token whose `aud`
 * differs. Without it, the server leaves the audience to Cloud Run IAM, so the
 * service must stay private, and it refuses to start off Cloud Run. Off Cloud
 * Run, use {@link newCustomAppHttpServer}.
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

/**
 * Builds an HTTPS server for a Custom Application connector, for any host
 * other than a private Cloud Run service:
 *
 * ```ts
 * const run = newCustomAppHttpServer({
 *   actions,
 *   connectorVersion: packageJson.version,
 * });
 * run();
 * ```
 *
 * The server requires `CONNECTOR_AUDIENCE` and rejects a token whose `aud`
 * differs.
 * @category Deployment
 */
export const newCustomAppHttpServer = (
  params: CustomAppConnectorParams
): (() => void) => {
  const router = newCustomAppConnectorRouter(params);
  const createContext = newConnectorContext();
  return () => runHttpConnector(CUSTOM_APP_NAMESPACE, router, createContext);
};
