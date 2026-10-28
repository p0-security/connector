import type { AnyRouter } from "@trpc/server";
import {
  type CreateExpressContextOptions,
  createExpressMiddleware,
} from "@trpc/server/adapters/express";
import { type RequestHandler, Router } from "express";

import { bearerAuthzMiddleware, runExpressApp } from "../http/index.ts";
import { entraInvokerConfigFromEnv, verifyEntraToken } from "./entra-token.ts";

/**
 * Creates an Azure Container Apps service that exposes a tRPC router over Express at
 * `/trpc`, gated by Entra bearer-token auth.
 *
 * Reads the expected caller from `P0_INVOKER_TENANT_ID` and `P0_INVOKER_CLIENT_ID`,
 * and throws before binding a port if either is missing.
 *
 * `GET /health` is the one route served without a token, for load balancer
 * health checks. It returns `{ module: moduleName }`.
 * @summary Creates an Azure Container Apps service that exposes a tRPC router over Express.
 * @category Cloud Functions
 *
 * @param moduleName Name reported by `/health` and used in logs.
 * @param router The tRPC router to mount.
 * @param createContext Optional context factory; receives the Express adapter's options.
 */
export const runAzureConnector = <T>(
  moduleName: string,
  router: AnyRouter,
  createContext?: (opts: CreateExpressContextOptions) => Promise<T>
) => {
  // Read the environment before serving, so a misconfigured connector fails to
  // start rather than answering every request with a 403.
  const verify = verifyEntraToken(entraInvokerConfigFromEnv());

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
