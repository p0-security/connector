/**
 * The contract P0's control plane builds its typed client against.
 *
 * The router is exported as a type only, so importing this loads no handler,
 * neither cloud's secret-manager SDK nor the 1Password SDK, and needs no
 * `DOMAIN_ALLOW_PATTERN`. The parsers are values: the control plane validates
 * with the same ones.
 */
import type { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export const OnePasswordConnectorSpec = connectorSpec;
export type OnePasswordConnectorSpec = typeof connectorSpec;
export type OnePasswordConnectorRouter = typeof connectorRouter;

export { spec as shareSpec } from "./accesses/share/definition.ts";
export {
  type InstallValidation as OnePasswordInstallValidation,
  installValidation,
} from "./install/definition.ts";
export {
  SHARE_DURATIONS,
  type ShareDuration,
  type ShareInput,
  type ShareOutput,
  shareDuration,
  shareInput,
  shareOutput,
} from "./share/definition.ts";
export {
  ONEPASSWORD_REFUSAL_REASONS,
  type OnePasswordRefusalReason,
  onePasswordRefusalReason,
} from "./refusals.ts";
