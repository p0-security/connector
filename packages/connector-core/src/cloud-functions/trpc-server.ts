import type { AnyRouter } from "@trpc/server";
import {
  type CreateExpressContextOptions,
  createExpressMiddleware,
} from "@trpc/server/adapters/express";
import { type RequestHandler, Router } from "express";

import { bearerAuthzMiddleware, runExpressApp } from "../http/index.ts";

/**
 * The tRPC server shared by `runCloudRunConnector` and `runHttpConnector`.
 * Doesn't depend on where it's hosted or how tokens are checked. Not exported
 * from the package index.
 */

/**
 * Checks the bearer token on a `/trpc` request. Resolves `true` to admit it.
 */
export type TokenVerifier = (token: string) => Promise<boolean>;

/**
 * Serves `router` at `/trpc`, plus `GET /health` without a token.
 *
 * With a `verify` function, every `/trpc` request needs a bearer token it
 * admits. With `null`, `/trpc` is served without any check, so the caller must
 * guarantee that something in front of the server authenticates requests.
 * `host` is passed to `runExpressApp`; leave it unset to listen on every
 * interface.
 */
export const serveTrpcConnector = <T>(
  moduleName: string,
  router: AnyRouter,
  createContext:
    ((opts: CreateExpressContextOptions) => Promise<T>) | undefined,
  verify: TokenVerifier | null,
  host?: string
) => {
  const trpcRouter = Router();
  trpcRouter.use(createExpressMiddleware({ router, createContext }));

  const middlewares: RequestHandler[] =
    verify === null ? [] : [bearerAuthzMiddleware(verify)];

  return runExpressApp(moduleName, { "/trpc": trpcRouter }, middlewares, host);
};
