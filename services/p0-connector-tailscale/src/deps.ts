import type { IdentityTokenSource } from "./tailscale/identity/source.ts";

/**
 * What differs between the connector's entry points. The Lambda (`index.ts`)
 * and Cloud Run (`run.ts`) each pass their cloud's identity token source, so
 * the router never asks which cloud it runs on.
 */
export type ConnectorDeps = {
  /** The connector's own cloud identity, for a federated credential. */
  identityToken: IdentityTokenSource;
};
