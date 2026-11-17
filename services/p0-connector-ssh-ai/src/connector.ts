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

export const SshAiConnectorSpec = connectorSpec;
export type SshAiConnectorSpec = typeof connectorSpec;
export type SshAiConnectorRouter = typeof connectorRouter;

export type { SessionSecret as SshAiSessionSecret } from "./accesses/session/definition.ts";
export {
  installContext,
  requestContext,
  type InstallContext as SshAiInstallContext,
  type RequestContext as SshAiRequestContext,
} from "./context.ts";
export {
  RUN_SCRIPT_FAILURES as SSH_AI_RUN_SCRIPT_FAILURES,
  SECRET_STEPS as SSH_AI_SECRET_STEPS,
  type RunScriptFailure as SshAiRunScriptFailure,
  type SecretStep as SshAiSecretStep,
} from "./failures.ts";
export {
  SSH_AI_INSTALL_STEPS,
  type InstallValidation as SshAiInstallValidation,
  type SshAiInstallStep,
} from "./install/definition.ts";
