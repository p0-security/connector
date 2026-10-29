/**
 * The contract the P0 control plane builds its typed client against: the
 * spec's parsers, the router's type, and the install validation types.
 *
 * A separate entry point from `index.ts`, which constructs the Lambda handler
 * on import. The control plane needs the contract, not the handler, so
 * nothing here loads the handler, the routers or the AWS SDK: the router is
 * imported for its type only.
 */
import type { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export const RedshiftAiConnectorSpec = connectorSpec;
export type RedshiftAiConnectorSpec = typeof connectorSpec;
export type RedshiftAiConnectorRouter = typeof connectorRouter;

export {
  TARGET_TYPES as REDSHIFT_AI_TARGET_TYPES,
  type InstallContext as RedshiftAiInstallContext,
  type RequestContext as RedshiftAiRequestContext,
  type TargetType as RedshiftAiTargetType,
} from "./context.ts";
export {
  REDSHIFT_AI_INSTALL_STEPS,
  type InstallValidation as RedshiftAiInstallValidation,
  type InstallWarning as RedshiftAiInstallWarning,
  type RedshiftAiInstallStep,
} from "./install/definition.ts";
export type { ObjectsRequestContext as RedshiftAiObjectsRequestContext } from "./accesses/objects/definition.ts";
