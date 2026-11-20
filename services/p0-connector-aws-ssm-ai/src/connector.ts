/**
 * The contract the P0 control plane builds its typed client against: the
 * spec's parsers, the router's type, the schemas of what it sends, and the
 * closed sets it reads off a failed call.
 *
 * A separate entry point from `index.ts`, which constructs the Lambda
 * handler on import. The control plane needs the contract, not the handler,
 * so nothing here loads the handler, the routers, the SSM client or the
 * secret manager client: it imports the router for its type only.
 */
import type { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export const AwsSsmAiConnectorSpec = connectorSpec;
export type AwsSsmAiConnectorSpec = typeof connectorSpec;
export type AwsSsmAiConnectorRouter = typeof connectorRouter;

export type { SessionSecret as AwsSsmAiSessionSecret } from "./accesses/session/definition.ts";
export {
  installContext,
  requestContext,
  type InstallContext as AwsSsmAiInstallContext,
  type RequestContext as AwsSsmAiRequestContext,
} from "./context.ts";
export {
  RUN_SCRIPT_FAILURES as AWS_SSM_AI_RUN_SCRIPT_FAILURES,
  SECRET_STEPS as AWS_SSM_AI_SECRET_STEPS,
  type RunScriptFailure as AwsSsmAiRunScriptFailure,
  type SecretStep as AwsSsmAiSecretStep,
} from "./failures.ts";
export {
  AWS_SSM_AI_INSTALL_STEPS,
  type InstallValidation as AwsSsmAiInstallValidation,
  type AwsSsmAiInstallStep,
} from "./install/definition.ts";
export {
  endSessionsInput,
  type EndSessionsInput as AwsSsmAiEndSessionsInput,
  type EndSessionsResult as AwsSsmAiEndSessionsResult,
} from "./sessions/definition.ts";
