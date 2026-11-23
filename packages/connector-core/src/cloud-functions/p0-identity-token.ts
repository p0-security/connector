import jwt from "jsonwebtoken";
import { type KeyObject, createPublicKey } from "node:crypto";
import { z } from "zod";

import {
  TokenRefusal,
  type TokenVerifier,
} from "../http/middlewares/bearer.ts";
import { createLogger } from "../logger.ts";

/**
 * Verifies the identity token P0 signs for a connector behind a trusted proxy,
 * against keys given in the environment. Makes no network request. Not
 * exported from the package index.
 */

const logger = createLogger();

const ISSUER = "p0";
const CLOCK_TOLERANCE_SECONDS = 60;
const MAX_LIFETIME_SECONDS = 15 * 60;
const MIN_MODULUS_BITS = 2048;

const jwksSchema = z.object({
  keys: z
    .array(
      z.object({
        kty: z.literal("RSA"),
        kid: z.string().min(1),
        alg: z.literal("RS256"),
        n: z.string().min(1),
        e: z.string().min(1),
      })
    )
    .min(1)
    .max(2),
});

/**
 * Parses `CONNECTOR_IDENTITY_JWKS`: one or two RSA keys of at least 2048 bits,
 * each with a distinct `kid` and `alg` `RS256`. Returns the keys by `kid`.
 *
 * Throws if the value is unset, empty or breaks any of those rules.
 */
export const identityKeysFromJwks = (
  value: string | undefined
): Map<string, KeyObject> => {
  if (!value) {
    throw new Error("CONNECTOR_IDENTITY_JWKS is not set");
  }
  let json: unknown;
  try {
    json = JSON.parse(value);
  } catch {
    throw new Error("CONNECTOR_IDENTITY_JWKS is not JSON");
  }
  const parsed = jwksSchema.safeParse(json);
  if (!parsed.success) {
    throw new Error(
      `CONNECTOR_IDENTITY_JWKS must be a key set of one or two RSA keys with alg RS256: ${z.prettifyError(parsed.error)}`
    );
  }
  const keys = new Map<string, KeyObject>();
  for (const { kid, kty, n, e } of parsed.data.keys) {
    if (keys.has(kid)) {
      throw new Error(`CONNECTOR_IDENTITY_JWKS has the kid ${kid} twice`);
    }
    let key: KeyObject;
    try {
      key = createPublicKey({ key: { kty, n, e }, format: "jwk" });
    } catch {
      throw new Error(
        `CONNECTOR_IDENTITY_JWKS key ${kid} is not a valid RSA public key`
      );
    }
    if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_MODULUS_BITS) {
      throw new Error(
        `CONNECTOR_IDENTITY_JWKS key ${kid} is shorter than ${MIN_MODULUS_BITS} bits`
      );
    }
    keys.set(kid, key);
  }
  return keys;
};

/**
 * Builds the check for P0's identity token: `RS256`, signed by the key its
 * `kid` names, `iss` `p0`, `aud` exactly `audience`, a `sub`, `iat` no more
 * than 60 seconds ahead, `exp` not past (with 60 seconds' leeway) and at most
 * 15 minutes after `iat`. Each failure throws a `TokenRefusal` naming the
 * check, never the token.
 */
export const newP0IdentityTokenVerifier = ({
  audience,
  keys,
}: {
  audience: string;
  keys: Map<string, KeyObject>;
}): TokenVerifier => {
  const fail = (check: string) =>
    new TokenRefusal(`P0 identity token refused: ${check}`);

  return async (token: string) => {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) {
      throw fail("not a JWT");
    }
    const { kid } = decoded.header;
    const key = kid === undefined ? undefined : keys.get(kid);
    if (!key) {
      throw fail("unknown kid");
    }
    let payload: jwt.JwtPayload | string;
    try {
      // Checks `alg`, the signature, `iss`, `exp` and any `nbf`.
      payload = jwt.verify(token, key, {
        algorithms: ["RS256"],
        issuer: ISSUER,
        clockTolerance: CLOCK_TOLERANCE_SECONDS,
      });
    } catch (err) {
      // jsonwebtoken's messages name the check ("invalid signature", "jwt
      // expired"), not the token.
      throw fail(err instanceof Error ? err.message : "jwt.verify failed");
    }
    if (typeof payload === "string") {
      throw fail("payload is not a JSON object");
    }
    if (payload.aud !== audience) {
      throw fail("wrong aud");
    }
    if (typeof payload.sub !== "string" || !payload.sub) {
      throw fail("no sub");
    }
    if (typeof payload.iat !== "number" || typeof payload.exp !== "number") {
      throw fail("no iat or exp");
    }
    if (payload.iat > Date.now() / 1000 + CLOCK_TOLERANCE_SECONDS) {
      throw fail("iat is in the future");
    }
    if (payload.exp - payload.iat > MAX_LIFETIME_SECONDS) {
      throw fail("lives longer than 15 minutes");
    }
    logger.info({ sub: payload.sub, kid }, "Admitted P0's identity token");
    return true;
  };
};
