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
  return async (token: string) => {
    const ticket = await client.verifyIdToken({
      idToken: token,
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
  const trpcRouter = Router();
  trpcRouter.use(
    createExpressMiddleware({
      router,
      createContext,
    })
  );

  const middlewares: RequestHandler[] = [
    bearerAuthzMiddleware(async (token: string) => {
      return verifyToken()(token);
    }),
  ];

  return runExpressApp(moduleName, { "/trpc": trpcRouter }, middlewares);
};
