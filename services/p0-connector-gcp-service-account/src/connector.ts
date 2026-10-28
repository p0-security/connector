/** The parsers and router type the P0 control plane builds its typed client
 * against.
 *
 * A separate entry point from `index.ts`, which constructs the Cloud Run
 * handler on import. The control plane needs the contract, not the server.
 */
import type { connectorRouter } from "./router.ts";

export { connectorRouter } from "./router.ts";
export type GcpServiceAccountConnectorRouter = typeof connectorRouter;

export { spec as agenticIdentitySpec } from "./accesses/agentic-identity/definition.ts";
