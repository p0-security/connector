/**
 * The contract the P0 control plane builds its typed client against: the
 * router's type, the access's parsers, the context types, the install
 * validation and the name patterns.
 *
 * A separate entry point from `index.ts`, which builds the Lambda handler on
 * import. The control plane needs the contract, not the handler, so nothing
 * here loads the routers, and nothing here may load a database driver or the
 * secret manager client: the router is imported for its type only.
 */
import type { connectorRouter } from "./router.ts";

export type PgVaultedConnectorRouter = typeof connectorRouter;

export { connectorSpec as PgVaultedConnectorSpec } from "./spec.ts";
export {
  GRANT_LOGIN_PATTERN,
  GRANT_SECRET_NAME_PATTERN,
  type InstallContext as PgVaultedInstallContext,
  type RequestContext as PgVaultedRequestContext,
  type Target as PgVaultedTarget,
} from "./context.ts";
export {
  PG_VAULTED_INSTALL_STEPS,
  installValidation as pgVaultedInstallValidation,
  type InstallValidation as PgVaultedInstallValidation,
  type PgVaultedInstallStep,
} from "./install/definition.ts";
