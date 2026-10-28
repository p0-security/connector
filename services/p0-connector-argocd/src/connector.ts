/**
 * The contract the P0 control plane builds its typed client against: the
 * router's type, each access's parsers, the instance schema it shares with
 * the connector, install validation's answer and steps, and the reasons a
 * refusal carries.
 *
 * A separate entry point from `index.ts`, which constructs the Lambda handler
 * on import. The control plane needs the contract, not the handler, so
 * nothing here loads the handler, the routers or the secret manager client:
 * the router is imported for its type only.
 */
import type { connectorRouter } from "./router.ts";

export type ArgoCdConnectorRouter = typeof connectorRouter;

export {
  instance as argoCdInstance,
  type Instance as ArgoCdInstance,
} from "./instance.ts";
export { spec as globalRoleSpec } from "./accesses/global-role/definition.ts";
export { spec as projectRoleSpec } from "./accesses/project-role/definition.ts";
export {
  ARGOCD_INSTALL_STEPS,
  argoCdInstallStep,
  installValidation as argoCdInstallValidation,
  type ArgoCdInstallStep,
  type InstallValidation as ArgoCdInstallValidation,
} from "./install/definition.ts";
export {
  ARGOCD_REFUSAL_REASONS,
  argoCdRefusalReason,
  type ArgoCdRefusalReason,
} from "./refusals.ts";
