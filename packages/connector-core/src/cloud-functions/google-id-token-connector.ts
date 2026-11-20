import type { AnyRouter } from "@trpc/server";
import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";
import { OAuth2Client } from "google-auth-library";

import { type TokenVerifier, serveTrpcConnector } from "./trpc-server.ts";

/**
 * The Google ID token verifier, and the tRPC server wrapper that takes one.
 * Used by `runCloudRunConnector` and `runHttpConnector`. Not exported from the
 * package index.
 */

/**
 * Builds the check for P0's Google ID token: signature, issuer, expiry, and an
 * `email` claim equal to `INVOKER_SA_EMAIL`. With an `audience`, the token's
 * `aud` must also equal it exactly. Without one, `aud` isn't compared.
 *
 * Throws if `INVOKER_SA_EMAIL` is unset or empty.
 */
export const newGoogleIdTokenVerifier = (audience?: string) => {
  const client = new OAuth2Client();
  const invokerSAEmail = process.env.INVOKER_SA_EMAIL ?? "";
  if (!invokerSAEmail) {
    throw new Error("Invoker service account email is not set or present");
  }
  return async (token: string) => {
    const ticket = await client.verifyIdToken(
      audience === undefined ? { idToken: token } : { idToken: token, audience }
    );
    const payload = ticket.getPayload();
    if (!payload || !payload.email) {
      return false;
    }
    const { email } = payload;
    return invokerSAEmail.toLocaleLowerCase() === email.toLowerCase();
  };
};

/**
 * Serves `router` at `/trpc` behind `verify`, plus `GET /health` without a
 * token. Listens on every interface.
 */
export const serveGoogleIdTokenConnector = <T>(
  moduleName: string,
  router: AnyRouter,
  createContext:
    ((opts: CreateExpressContextOptions) => Promise<T>) | undefined,
  verify: TokenVerifier
) => serveTrpcConnector(moduleName, router, createContext, verify);
