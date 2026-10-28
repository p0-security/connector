/**
 * The contract the P0 control plane builds its typed client against: the
 * router's type and the accesses' parsers.
 *
 * A separate entry point from `index.ts`, which builds the handler, and with
 * it the Snowflake client, on import. The control plane needs the contract,
 * not the handler, so nothing here loads `snowflake-sdk`, the routers or the
 * secret manager client: the router is imported for its type only.
 */
import type { connectorRouter } from "./router.ts";

export type SnowflakeAiConnectorRouter = typeof connectorRouter;

export { connectorSpec as SnowflakeAiConnectorSpec } from "./spec.ts";
export type {
  InstallContext as SnowflakeAiInstallContext,
  RequestContext as SnowflakeAiRequestContext,
} from "./context.ts";
export {
  SNOWFLAKE_AI_INSTALL_STEPS,
  installValidation as snowflakeAiInstallValidation,
  type InstallValidation as SnowflakeAiInstallValidation,
  type SnowflakeAiInstallStep,
} from "./install/definition.ts";
