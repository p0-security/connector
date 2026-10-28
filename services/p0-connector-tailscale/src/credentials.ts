import { z } from "zod";

/**
 * The tailnet the connector acts on, as Tailscale's API names it in a path:
 * the Tailnet ID from Settings > General (such as `T1234CNTRL`), `-` for the
 * credential's own tailnet, or the legacy ID a tailnet created before October
 * 2025 still answers to (such as `example.com` or `alice@gmail.com`). Never
 * the DNS name (`tail1234.ts.net`), which the API doesn't take.
 *
 * It becomes one URL path segment, so nothing but letters, digits and
 * `.`, `_`, `@`, `+` and `-` gets in.
 */
export const TAILNET_PATTERN = /^(?:-|[A-Za-z0-9][A-Za-z0-9._@+-]{0,252})$/;

export const tailnet = z
  .string()
  .regex(
    TAILNET_PATTERN,
    "must be the Tailnet ID from Tailscale's Settings > General, such as T1234CNTRL"
  )
  .refine(
    (value) => !/\.ts\.net$/i.test(value),
    "must be the Tailnet ID from Tailscale's Settings > General, such as T1234CNTRL, not the tailnet's DNS name"
  );

// A Tailscale OAuth client or federated identity id, such as `kAbc1CNTRL`. It
// only ever goes into a form body, and P0 derives the federated audience
// from it, so nothing but letters, digits, `_` and `-` gets in.
const clientId = z
  .string()
  .regex(/^[A-Za-z0-9_-]{1,128}$/, "must be a Tailscale client ID");

/**
 * Where an OAuth client's secret is, in the customer's own secret manager. A
 * pointer, never the secret: the connector reads it itself.
 */
export const secretPointer = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    secretId: z.string().min(1),
    region: z.string().min(1),
  }),
  z.object({
    manager: z.literal("gcp"),
    secretId: z.string().min(1),
    projectId: z.string().min(1),
  }),
]);

export type SecretPointer = z.infer<typeof secretPointer>;

/**
 * The Tailscale credential the connector uses:
 *
 * - `federated`: a federated identity that trusts the connector's own cloud
 *   identity. Nothing is stored. The audience is Tailscale's default,
 *   `api.tailscale.com/<clientId>`.
 * - `vault`: an OAuth client whose secret is in the customer's secret
 *   manager.
 */
export const credential = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("federated"), clientId }),
  z.object({ kind: z.literal("vault"), clientId, secret: secretPointer }),
]);

export type Credential = z.infer<typeof credential>;

/**
 * What the connector needs to act on one tailnet. The customer's policy
 * file gates grants on P0 postures, and P0 only sets device attributes: it
 * never writes the policy file.
 */
export const tailnetCredentials = z.object({ tailnet, credential });

export type TailnetCredentials = z.infer<typeof tailnetCredentials>;
