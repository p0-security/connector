import { z } from "zod";

/**
 * The tenant's canonical domain, `<name>[.<region>].auth0.com`. It becomes the
 * host of every URL the connector calls, so nothing else gets in: no custom
 * domain, no port, no path, and nothing upper-case.
 *
 * Custom domains are refused because the Management API's audience is always
 * the canonical domain, and the token and the API calls must use the same one.
 */
export const TENANT_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z]{2})?\.auth0\.com$/;

export const tenant = z
  .string()
  .regex(
    TENANT_PATTERN,
    "must be the tenant's canonical Auth0 domain, such as acme.us.auth0.com"
  );

// A client id only ever goes into a request body. Even so, one with anything
// but letters, digits, `_` and `-` is refused.
const clientId = z
  .string()
  .regex(/^[A-Za-z0-9_-]{1,128}$/, "must be an Auth0 client id");

/**
 * Where the client secret is, in the customer's own secret manager. A
 * pointer, never the secret: the connector reads it itself.
 */
export const clientSecret = z.discriminatedUnion("manager", [
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

export type ClientSecret = z.infer<typeof clientSecret>;

/**
 * What the connector needs to act on one Auth0 tenant: the tenant, the client
 * id of its Management API machine-to-machine application, and where that
 * application's client secret is.
 */
export const tenantCredentials = z.object({ tenant, clientId, clientSecret });

export type TenantCredentials = z.infer<typeof tenantCredentials>;
