/**
 * The contract the P0 control plane builds its typed client against: the
 * router's type and the contract's parsers and types.
 *
 * A separate entry point from `index.ts`, which builds the Lambda handler on
 * import. The control plane needs the contract, not the handler, so nothing
 * here loads the routers, and nothing here may load a database driver or the
 * Secrets Manager client: the router is imported for its type only.
 */
import type { connectorRouter } from "./router.ts";

export type PgVaultedConnectorRouter = typeof connectorRouter;

export {
  PG_VAULTED_INSTALL_STEPS,
  type InstallContext as PgVaultedInstallContext,
  installValidation as pgVaultedInstallValidation,
  type InstallValidation as PgVaultedInstallValidation,
  type PgVaultedInstallStep,
  type Target as PgVaultedTarget,
} from "./install/definition.ts";
