/**
 * The contract P0's control plane builds its typed client against.
 *
 * The router is exported as a type only, so importing this loads no handler
 * and neither cloud's secret-manager SDK, and needs no `DOMAIN_ALLOW_PATTERN`.
 * The parsers are values: the control plane validates with the same ones.
 */
import type { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export const DockerConnectorSpec = connectorSpec;
export type DockerConnectorSpec = typeof connectorSpec;
export type DockerConnectorRouter = typeof connectorRouter;

export { spec as roleSpec } from "./accesses/role/definition.ts";
export {
  type InstallValidation as DockerInstallValidation,
  installValidation,
} from "./install/definition.ts";
