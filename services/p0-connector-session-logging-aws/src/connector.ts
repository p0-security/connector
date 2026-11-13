/**
 * The contract the P0 control plane builds its typed client against: the
 * router's type and the install validation types. The `logs` route's types
 * come from `@p0security/connector-core`.
 *
 * A separate entry point from `index.ts`, which constructs the Lambda handler
 * on import. Nothing here loads the handler, the routers or the AWS SDK: the
 * router is imported for its type only.
 */
import type { connectorRouter } from "./router.ts";

export type AwsCloudWatchConnectorRouter = typeof connectorRouter;

export {
  AWS_CLOUDWATCH_INSTALL_STEPS,
  CLOUDTRAIL_COVERAGES,
  type AwsCloudWatchInstallStep,
  type InstallInput as AwsCloudWatchInstallInput,
  type InstallValidation as AwsCloudWatchInstallValidation,
  type InstallWarning as AwsCloudWatchInstallWarning,
} from "./install/definition.ts";
