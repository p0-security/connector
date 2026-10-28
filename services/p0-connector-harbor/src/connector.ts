/**
 * The contract the P0 control plane builds its typed client against: the
 * router's type, the project role and system administrator accesses' parsers,
 * and the schemas and types it shares with the connector.
 *
 * A separate entry point from `index.ts`, which constructs the Lambda handler
 * on import. The control plane needs the contract, not the handler, so
 * nothing here loads the handler, the routers or the secret manager client:
 * the router is imported for its type only.
 */
import type { connectorRouter } from "./router.ts";

export type HarborConnectorRouter = typeof connectorRouter;

export {
  harborRole,
  instance as harborInstance,
  spec as projectRoleSpec,
  type HarborRole,
  type Instance as HarborInstance,
} from "./accesses/project-role/definition.ts";
export {
  harborAdminState,
  spec as systemAdminSpec,
  type HarborAdminState,
} from "./accesses/system-admin/definition.ts";
export {
  installValidation,
  type InstallValidation as HarborInstallValidation,
} from "./install/definition.ts";
export {
  HARBOR_REFUSAL_REASONS,
  harborRefusalReason,
  type HarborRefusalReason,
} from "./refusals.ts";
