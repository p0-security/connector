import type { AnyRouter } from "@trpc/server";
import {
  type CreateExpressContextOptions,
  createExpressMiddleware,
} from "@trpc/server/adapters/express";
import { type RequestHandler, Router } from "express";
import { OAuth2Client } from "google-auth-library";

import { AUDIENCE_CHECK_CONTEXT_KEY } from "../audience-check.ts";
import { bearerAuthzMiddleware, runExpressApp } from "../http/index.ts";

/**
 * Shared by `runCloudRunConnector` and `runHttpConnector`, which differ only
 * in how they decide the audience. Not exported from the package index.
 */

/**
 * Reads `CONNECTOR_AUDIENCE`. Returns `undefined` when it's unset, and throws
 * when it's set to a value that would reject every token.
 */
export const connectorAudienceFromEnv = (): string | undefined => {
  const audience = process.env.CONNECTOR_AUDIENCE;
  if (audience === undefined) return undefined;
  // google-auth-library compares the audience whenever one is passed, so an
  // empty string would reject every token. Surrounding whitespace (say, a
  // trailing newline from a secret) would do the same. Refuse it rather than
  // trim it, since the value must match what P0 mints.
  if (!audience) {
    throw new Error("Connector audience is not set or present");
  }
  if (audience !== audience.trim()) {
    throw new Error("Connector audience has leading or trailing whitespace");
  }
  return audience;
};

/**
 * Builds the check for P0's Google ID token: signature, issuer, expiry, and an
 * `email` claim equal to `INVOKER_SA_EMAIL`. With an `audience`, the token's
 * `aud` must also equal it exactly; without one, `aud` isn't compared.
 *
 * Throws if `INVOKER_SA_EMAIL` is unset or empty.
 */
const newGoogleIdTokenVerifier = (audience: string | undefined) => {
  const client = new OAuth2Client();
  const invokerSAEmail = process.env.INVOKER_SA_EMAIL ?? "";
  if (!invokerSAEmail) {
    throw new Error("Invoker service account email is not set or present");
  }
  return async (token: string) => {
    // Without an audience, google-auth-library still checks the signature,
    // issuer and expiry; only the `aud` comparison is skipped.
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
 * Serves `router` at `/trpc` behind the Google ID token check, plus
 * `GET /health` without a token.
 *
 * The context each procedure receives is a shallow copy of what
 * `createContext` returns (an empty object without one), with whether the
 * audience is checked added under a private key for `app.metadata.get`.
 */
export const serveGoogleIdTokenConnector = <T>(
  moduleName: string,
  router: AnyRouter,
  createContext:
    ((opts: CreateExpressContextOptions) => Promise<T>) | undefined,
  audience: string | undefined
) => {
  // Read the environment before serving, so a misconfigured connector fails to
  // start rather than answering every request with a 403.
  const verify = newGoogleIdTokenVerifier(audience);
  const audienceCheck = audience !== undefined;

  const trpcRouter = Router();
  trpcRouter.use(
    createExpressMiddleware({
      router,
      // Hand the mode to `app.metadata.get` through the context, since the
      // router is built before this runs.
      createContext: async (opts: CreateExpressContextOptions) =>
        Object.assign({}, await createContext?.(opts), {
          [AUDIENCE_CHECK_CONTEXT_KEY]: audienceCheck,
        }),
    })
  );

  const middlewares: RequestHandler[] = [bearerAuthzMiddleware(verify)];

  return runExpressApp(moduleName, { "/trpc": trpcRouter }, middlewares);
};
