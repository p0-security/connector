/**
 * The contract the P0 control plane builds its typed client against: the
 * router's type, the team and install schemas, and the refusal reasons.
 *
 * A separate entry point from `index.ts`, which constructs the Lambda handler
 * on import. The control plane needs the contract, not the handler, so
 * nothing here loads the handler, the routers or the secret manager client:
 * the router is imported for its type only.
 */
import type { connectorRouter } from "./router.ts";

export type MiroConnectorRouter = typeof connectorRouter;

export {
  installInput,
  secretPointer,
  team,
  type InstallInput as MiroInstallInput,
  type Team as MiroTeam,
} from "./team.ts";
export {
  installValidation,
  type InstallValidation as MiroInstallValidation,
} from "./install/definition.ts";
export {
  MIRO_REFUSAL_REASONS,
  miroRefusalReason,
  type MiroRefusalReason,
} from "./refusals.ts";
