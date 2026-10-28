/**
 * The contract the P0 control plane builds its typed client against: the
 * router's type, the account and install schemas, the `base-role` access's
 * parsers, and the refusal reasons.
 *
 * A separate entry point from `index.ts`, which constructs the Lambda handler
 * on import. The control plane needs the contract, not the handler, so
 * nothing here loads the handler, the routers or the secret manager client:
 * the router is imported for its type only.
 */
import type { connectorRouter } from "./router.ts";

export type LaunchDarklyConnectorRouter = typeof connectorRouter;

export {
  account,
  installInput,
  secretPointer,
  type Account as LaunchDarklyAccount,
  type InstallInput as LaunchDarklyInstallInput,
} from "./account.ts";
export { spec as baseRoleSpec } from "./accesses/base-role/definition.ts";
export {
  type BaseRequestContext as LaunchDarklyRequestContext,
  type UserBody as LaunchDarklyUserBody,
} from "./accesses/common/definition.ts";
export {
  installValidation,
  type InstallValidation as LaunchDarklyInstallValidation,
} from "./install/definition.ts";
export {
  LAUNCHDARKLY_REFUSAL_REASONS,
  launchDarklyRefusalReason,
  type LaunchDarklyRefusalReason,
} from "./refusals.ts";
