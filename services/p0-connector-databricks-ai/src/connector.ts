/**
 * The contract the P0 control plane builds its typed client against: the
 * spec's parsers, the router's type, and the install validation types.
 *
 * A separate entry point from `index.ts`, which constructs the Lambda handler
 * on import. The control plane needs the contract, not the handler, so
 * nothing here loads the handler, the routers or `@aws-sdk/client-sts`: the
 * router is imported for its type only.
 */
import type { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export const DatabricksAiConnectorSpec = connectorSpec;
export type DatabricksAiConnectorSpec = typeof connectorSpec;
export type DatabricksAiConnectorRouter = typeof connectorRouter;

export {
  type ListerQuery as DatabricksAiDataListerQuery,
  type Policy as DatabricksAiDataPolicy,
  type RequestContext as DatabricksAiDataRequestContext,
  type RequestGrant as DatabricksAiDataRequestGrant,
  type Securable as DatabricksAiDataSecurable,
} from "./accesses/data/definition.ts";
export {
  type InstallValidation as DatabricksAiInstallValidation,
  type InstallValidationInput as DatabricksAiInstallValidationInput,
  type MetastoreAdmin as DatabricksAiMetastoreAdmin,
  type OwnerPrincipal as DatabricksAiOwnerPrincipal,
  type Probe as DatabricksAiProbe,
  type ProbeInput as DatabricksAiProbeInput,
  type Stage as DatabricksAiStage,
  type StageInput as DatabricksAiStageInput,
} from "./install/definition.ts";
