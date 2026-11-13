/**
 * The contract the P0 control plane builds its typed client against: the
 * router's type and the install validation types. The `logs` route's types
 * come from `@p0security/connector-core`.
 *
 * Nothing here loads the server or the routers: the router is imported for
 * its type only.
 */
import type { connectorRouter } from "./router.ts";

export type GcpCloudLoggingConnectorRouter = typeof connectorRouter;

export {
  GCP_CLOUD_LOGGING_INSTALL_STEPS,
  type GcpCloudLoggingInstallStep,
  type InstallInput as GcpCloudLoggingInstallInput,
  type InstallValidation as GcpCloudLoggingInstallValidation,
} from "./install/definition.ts";
