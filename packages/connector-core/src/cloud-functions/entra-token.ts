import jwt from "jsonwebtoken";
import { type KeyObject, createPublicKey } from "node:crypto";
import { z } from "zod";

const ENTRA_AUTHORITY = "https://login.microsoftonline.com";

// Entra rolls its signing keys over, so refetch the key set when a token names
// a key we don't have, but no more often than this.
const JWKS_REFETCH_COOLDOWN_MS = 5 * 60 * 1000;
// Refetch at least this often, so a key Entra withdraws stops being trusted.
const JWKS_MAX_AGE_MS = 24 * 60 * 60 * 1000;

const jwksSchema = z.object({
  keys: z.array(
    z.object({
      kid: z.string(),
      kty: z.string(),
      use: z.string().optional(),
      n: z.string().optional(),
      e: z.string().optional(),
    })
  ),
});

/** The Entra app registration that P0's Control plane gets its tokens for. */
export type EntraInvokerConfig = {
  /** The customer's Entra tenant ID. Pins the token's `iss`. */
  tenantId: string;
  /** The Connector's own app registration. Pins the token's `aud` and `azp`. */
  clientId: string;
};

/**
 * Reads the inbound auth config from `P0_INVOKER_TENANT_ID` and `P0_INVOKER_CLIENT_ID`.
 *
 * This deliberately doesn't read `AZURE_CLIENT_ID`: `DefaultAzureCredential` treats
 * that as the Connector's own managed identity for outbound calls.
 *
 * @throws if either variable is missing
 */
export const entraInvokerConfigFromEnv = (): EntraInvokerConfig => {
  const tenantId = process.env.P0_INVOKER_TENANT_ID;
  const clientId = process.env.P0_INVOKER_CLIENT_ID;
  const missing = [
    ...(tenantId ? [] : ["P0_INVOKER_TENANT_ID"]),
    ...(clientId ? [] : ["P0_INVOKER_CLIENT_ID"]),
  ];
  if (!tenantId || !clientId) {
    throw new Error(`Missing required environment: ${missing.join(", ")}`);
  }
  return { tenantId, clientId };
};

export const entraIssuer = (tenantId: string) =>
  `${ENTRA_AUTHORITY}/${tenantId}/v2.0`;

const entraJwksUri = (tenantId: string) =>
  `${ENTRA_AUTHORITY}/${tenantId}/discovery/v2.0/keys`;

/** Looks up a tenant's signing keys by `kid`, caching the key set between calls. */
const newJwksKeyResolver = (jwksUri: string) => {
  let keys = new Map<string, KeyObject>();
  let fetchedAt = 0;
  let pending: Promise<void> | undefined;

  const refresh = async () => {
    const response = await fetch(jwksUri);
    if (!response.ok) {
      throw new Error(`Failed to fetch ${jwksUri}: HTTP ${response.status}`);
    }
    const jwks = jwksSchema.parse(await response.json());
    keys = new Map(
      jwks.keys
        .filter((key) => key.kty === "RSA" && (key.use ?? "sig") === "sig")
        .map(({ kid, kty, n, e }) => [
          kid,
          createPublicKey({ key: { kty, n, e }, format: "jwk" }),
        ])
    );
    fetchedAt = Date.now();
  };

  return async (kid: string) => {
    const age = Date.now() - fetchedAt;
    if (
      age > JWKS_MAX_AGE_MS ||
      (!keys.has(kid) && age > JWKS_REFETCH_COOLDOWN_MS)
    ) {
      pending ??= refresh().finally(() => (pending = undefined));
      await pending;
    }
    const key = keys.get(kid);
    if (!key) {
      throw new Error(`Token signing key ${kid} is not in ${jwksUri}`);
    }
    return key;
  };
};

/**
 * Verifies the Entra v2 access tokens the Control plane sends a Connector on Azure.
 *
 * Checks the signature against the tenant's JWKS, then `iss`, `aud`, `azp`, `exp`
 * and `nbf`. It looks only at the raw bearer token, never at Easy Auth's
 * `x-ms-client-principal*` headers, so it holds even if Easy Auth is off or
 * misconfigured.
 *
 * @returns a function that resolves `true` for a valid token, and otherwise
 * resolves `false` or throws
 */
export const verifyEntraToken = ({
  tenantId,
  clientId,
}: EntraInvokerConfig) => {
  const issuer = entraIssuer(tenantId);
  const getKey = newJwksKeyResolver(entraJwksUri(tenantId));

  return async (token: string) => {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded?.header.kid) {
      return false;
    }
    const key = await getKey(decoded.header.kid);
    // Checks the signature, `iss`, `aud`, `exp` and `nbf`, and throws on any failure.
    const payload = jwt.verify(token, key, {
      algorithms: ["RS256"],
      issuer,
      audience: clientId,
    });
    if (typeof payload === "string") {
      return false;
    }
    // The token is for the Connector's own app registration, so the caller and
    // the audience are the same app.
    return payload.azp === clientId;
  };
};
