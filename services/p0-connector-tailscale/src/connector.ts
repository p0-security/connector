/**
 * The contract P0's control plane builds its typed client against.
 *
 * The router is exported as a type only, so importing this loads no handler
 * and neither cloud's SDK. The parsers are values: the control plane
 * validates with the same ones.
 */
import type { newTailscaleRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export const TailscaleConnectorSpec = connectorSpec;
export type TailscaleConnectorSpec = typeof connectorSpec;
export type TailscaleConnectorRouter = ReturnType<typeof newTailscaleRouter>;

export {
  type Credential as TailscaleCredential,
  type SecretPointer as TailscaleSecretPointer,
  TAILNET_PATTERN as TAILSCALE_TAILNET_PATTERN,
  type TailnetCredentials as TailscaleTailnetCredentials,
  tailnetCredentials as tailscaleTailnetCredentials,
} from "./credentials.ts";
export { REQUIRED_SCOPES as TAILSCALE_REQUIRED_SCOPES } from "./tailscale/scopes.ts";
export {
  type InstallValidation as TailscaleInstallValidation,
  type InstallValidationInput as TailscaleInstallValidationInput,
  installValidation,
  installValidationInput as tailscaleInstallValidationInput,
} from "./install/definition.ts";
export {
  type ListerQuery as TailscaleListerQuery,
  type ListerResponse as TailscaleListerResponse,
} from "./accesses/common/definition.ts";
export {
  type Destination as TailscaleDestination,
  type DestinationCheck as TailscaleDestinationCheck,
  type DestinationCheckInput as TailscaleDestinationCheckInput,
  type UnlockedGrant as TailscaleUnlockedGrant,
  type UnlockedSshRule as TailscaleUnlockedSshRule,
  type Unlocks as TailscaleUnlocks,
  destination as tailscaleDestination,
  destinationCheck,
  unlockedGrant as tailscaleUnlockedGrant,
  unlockedSshRule as tailscaleUnlockedSshRule,
  unlocks as tailscaleUnlocks,
} from "./destinations/definition.ts";
export {
  type Destination as TailscalePostureDestination,
  type PostureContext as TailscalePostureContext,
  attributeKeyFor as tailscaleAttributeKeyFor,
  spec as postureSpec,
} from "./accesses/posture/definition.ts";
