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
 * The server doesn't check the token's audience. Cloud Run IAM does, so the
 * service must stay private. Off Cloud Run, use {@link newCustomAppHttpServer}.
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
 * Builds a server for a Custom Application connector, for any host other than
 * a private Cloud Run service:
 *
 * ```ts
 * const run = newCustomAppHttpServer({
 *   actions,
 *   connectorVersion: packageJson.version,
 * });
 * run();
 * ```
 *
 * The server speaks plain HTTP on `$PORT`. `CONNECTOR_AUTH` picks how it
 * authenticates requests:
 *
 * - `google-id-token` (the default when unset): the server requires
 *   `INVOKER_SA_EMAIL` and `CONNECTOR_AUDIENCE`, and rejects a token whose
 *   `aud` differs. It listens on every interface, so put it behind something
 *   that terminates TLS.
 * - `gateway`: the server checks no token. It trusts a proxy on the same host
 *   to authenticate every request, and listens on `127.0.0.1` unless
 *   `CONNECTOR_BIND_ADDRESS` says otherwise. Anything that can reach its port
 *   can call your actions.
 *
 * `run()` throws before binding a port if `CONNECTOR_AUTH` has any other
 * value.
 * @category Deployment
 */
export const newCustomAppHttpServer = (
  params: CustomAppConnectorParams
): (() => void) => {
  const router = newCustomAppConnectorRouter(params);
  const createContext = newConnectorContext();
  return () => runHttpConnector(CUSTOM_APP_NAMESPACE, router, createContext);
};
