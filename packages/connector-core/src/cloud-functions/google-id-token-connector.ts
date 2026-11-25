import { OAuth2Client } from "google-auth-library";

import {
  TokenRefusal,
  type TokenVerifier,
  failedCheck,
} from "../http/middlewares/bearer.ts";

/**
 * The Google ID token verifier used by `runCloudRunConnector` and
 * `runHttpConnector`. Not exported from the package index.
 */

/**
 * The start of each error google-auth-library 10.x throws for a token it
 * refuses, with the check it names. Several of these messages go on to quote
 * the token or its payload, so only the name is logged. Any other error is
 * logged as "Token verification failed".
 */
const GOOGLE_CHECKS = [
  ["Wrong number of segments in token", "malformed token"],
  ["Can't parse token envelope", "malformed token"],
  ["Can't parse token payload", "malformed token"],
  ["No pem found for envelope", "unknown kid"],
  ["Invalid token signature", "invalid signature"],
  ["No issue time in token", "no iat or exp"],
  ["No expiration time in token", "no iat or exp"],
  ["Expiration time too far in future", "lives too long"],
  ["Token used too early", "not yet valid"],
  ["Token used too late", "expired"],
  ["Invalid issuer", "wrong iss"],
  ["Wrong recipient", "wrong aud"],
  ["Failed to retrieve verification certificates", "certificate fetch failed"],
] as const;

/**
 * Builds the check for P0's Google ID token: signature, issuer, expiry, and an
 * `email` claim equal to `INVOKER_SA_EMAIL`. With an `audience`, the token's
 * `aud` must also equal it exactly. Without one, `aud` isn't compared. A
 * failure it recognises throws a `TokenRefusal` naming the check, never the
 * token or the email.
 *
 * Throws if `INVOKER_SA_EMAIL` is unset or empty.
 */
export const newGoogleIdTokenVerifier = (audience?: string): TokenVerifier => {
  const client = new OAuth2Client();
  const invokerSAEmail = process.env.INVOKER_SA_EMAIL ?? "";
  if (!invokerSAEmail) {
    throw new Error("Invoker service account email is not set or present");
  }
  const fail = (check: string) =>
    new TokenRefusal(`Google ID token refused: ${check}`);

  return async (token: string) => {
    let ticket;
    try {
      ticket = await client.verifyIdToken(
        audience === undefined
          ? { idToken: token }
          : { idToken: token, audience }
      );
    } catch (err) {
      const check = failedCheck(err, GOOGLE_CHECKS);
      if (check) {
        throw fail(check);
      }
      throw err;
    }
    const payload = ticket.getPayload();
    if (!payload?.email) {
      throw fail("no email claim");
    }
    if (invokerSAEmail.toLocaleLowerCase() !== payload.email.toLowerCase()) {
      throw fail("wrong email");
    }
    return true;
  };
};
