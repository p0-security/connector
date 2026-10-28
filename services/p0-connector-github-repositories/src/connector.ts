/** The parsers and router type the P0 control plane builds its typed client
 * against.
 *
 * A separate entry point from `index.ts`, which constructs the Lambda handler
 * on import. The control plane needs the contract, not the handler.
 */
import type { connectorRouter } from "./router.ts";

export { connectorRouter } from "./router.ts";
export type GitHubRepositoriesConnectorRouter = typeof connectorRouter;

export { spec as roleSpec } from "./accesses/role/definition.ts";
export {
  type InstallValidation as GitHubRepositoriesInstallValidation,
  installValidation,
} from "./install/definition.ts";
