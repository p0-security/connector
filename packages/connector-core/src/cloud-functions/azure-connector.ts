import { bearerAuthzMiddleware, runExpressApp } from "@p0security/sp-shared";
import type { AnyRouter } from "@trpc/server";
import {
  type CreateExpressContextOptions,
  createExpressMiddleware,
} from "@trpc/server/adapters/express";
import { type RequestHandler, Router } from "express";

import { entraInvokerConfigFromEnv, verifyEntraToken } from "./entraToken.ts";

/**
 * Creates an Azure Container Apps service that exposes a tRPC router over Express at
 * `/trpc`, gated by Entra bearer-token auth and with a `/health` endpoint.
 *
 * Reads the expected caller from `P0_INVOKER_TENANT_ID` and `P0_INVOKER_CLIENT_ID`,
 * and refuses to start if either is missing, unless `SKIP_VERIFY_TOKEN` is set for
 * local development.
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
  const trpcRouter = Router();
  trpcRouter.use(
    createExpressMiddleware({
      router,
      createContext,
    })
  );

  const middlewares: RequestHandler[] = [];
  if (!process.env.SKIP_VERIFY_TOKEN) {
    middlewares.push(
      bearerAuthzMiddleware(verifyEntraToken(entraInvokerConfigFromEnv()))
    );
  }

  return runExpressApp(moduleName, { "/trpc": trpcRouter }, middlewares);
};
