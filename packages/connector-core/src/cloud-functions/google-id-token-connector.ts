import type { AnyRouter } from "@trpc/server";
import {
  type CreateExpressContextOptions,
  createExpressMiddleware,
} from "@trpc/server/adapters/express";
import { type RequestHandler, Router } from "express";
import { OAuth2Client } from "google-auth-library";

import { bearerAuthzMiddleware, runExpressApp } from "../http/index.ts";

/**
 * Shared by `runCloudRunConnector` and `runHttpConnector`. Not exported from
 * the package index.
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
 * token.
 */
export const serveGoogleIdTokenConnector = <T>(
  moduleName: string,
  router: AnyRouter,
  createContext:
    ((opts: CreateExpressContextOptions) => Promise<T>) | undefined,
  verify: (token: string) => Promise<boolean>
) => {
  const trpcRouter = Router();
  trpcRouter.use(createExpressMiddleware({ router, createContext }));

  const middlewares: RequestHandler[] = [bearerAuthzMiddleware(verify)];

  return runExpressApp(moduleName, { "/trpc": trpcRouter }, middlewares);
};
