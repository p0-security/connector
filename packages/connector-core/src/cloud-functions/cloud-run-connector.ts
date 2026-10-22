import type { AnyRouter } from "@trpc/server";
import {
  type CreateExpressContextOptions,
  createExpressMiddleware,
} from "@trpc/server/adapters/express";
import { type RequestHandler, Router } from "express";
import { OAuth2Client } from "google-auth-library";

import { bearerAuthzMiddleware, runExpressApp } from "../http/index.ts";

const verifyToken = () => {
  const client = new OAuth2Client();
  const invokerSAEmail = process.env.INVOKER_SA_EMAIL ?? "";
  if (!invokerSAEmail) {
    throw new Error("Invoker service account email is not set or present");
  }
  // google-auth-library compares the audience whenever one is passed, so an
  // empty string would reject every token; treat it as unset.
  const audience = process.env.CONNECTOR_AUDIENCE ?? "";
  if (!audience) {
    throw new Error("Connector audience is not set or present");
  }
  return async (token: string) => {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience,
    });
    const payload = ticket.getPayload();
    if (!payload || !payload.email) {
      return false;
    }
    const { email } = payload;
    return invokerSAEmail.toLocaleLowerCase() === email.toLowerCase();
  };
};

/**
 * Creates a Cloud Run service that exposes a tRPC router over Express at
 * `/trpc`, gated by bearer-token auth.
 *
 * Requests must carry a Google-signed ID token whose `email` claim is
 * `$INVOKER_SA_EMAIL` and whose `aud` claim is exactly `$CONNECTOR_AUDIENCE`.
 * Throws before binding a port if either variable is unset or empty.
 * @summary Creates a Cloud Run service that exposes a tRPC router over Express.
 * @category Cloud Functions
 *
 * @param moduleName Name reported by `/health` and used in logs.
 * @param router The tRPC router to mount.
 * @param createContext Optional context factory; receives the Express adapter's options.
 */
export const runCloudRunConnector = <T>(
  moduleName: string,
  router: AnyRouter,
  createContext?: (opts: CreateExpressContextOptions) => Promise<T>
) => {
  // Read the environment before serving, so a misconfigured connector fails to
  // start rather than answering every request with a 403.
  const verify = verifyToken();

  const trpcRouter = Router();
  trpcRouter.use(
    createExpressMiddleware({
      router,
      createContext,
    })
  );

  const middlewares: RequestHandler[] = [bearerAuthzMiddleware(verify)];

  return runExpressApp(moduleName, { "/trpc": trpcRouter }, middlewares);
};
