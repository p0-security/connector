/**
 * Mints the connector's own cloud identity token for `audience`, which the
 * Tailscale federated identity trusts. Each entry point passes its cloud's:
 * the Lambda's (`aws.ts`) or Cloud Run's (`gcp.ts`). The token is a
 * credential: it goes to Tailscale's token exchange and nowhere else.
 */
export type IdentityTokenSource = (audience: string) => Promise<string>;

/**
 * The audience Tailscale generates for a federated identity, which P0 always
 * uses: the install has no audience field.
 */
export const federatedAudience = (clientId: string): string =>
  `api.tailscale.com/${clientId}`;
