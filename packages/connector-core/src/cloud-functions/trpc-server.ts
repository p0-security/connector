import type { AnyRouter } from "@trpc/server";
import {
  type CreateExpressContextOptions,
  createExpressMiddleware,
} from "@trpc/server/adapters/express";
import { Router } from "express";

import { bearerAuthzMiddleware, runExpressApp } from "../http/index.ts";
import type { TokenVerifier } from "../http/middlewares/bearer.ts";

/**
 * The tRPC server shared by `runCloudRunConnector` and `runHttpConnector`.
 * Doesn't depend on where it's hosted or how tokens are checked. Not exported
 * from the package index.
 */

/**
 * Serves `router` at `/trpc`, where every request needs a bearer token in
 * `tokenHeader` (default `authorization`) that `verify` admits, plus
 * `GET /health` without a token. Listens on `host`, or on every interface
 * when it's unset.
 */
export const serveTrpcConnector = <T>({
  moduleName,
  router,
  createContext,
  verify,
  tokenHeader,
  host,
}: {
  moduleName: string;
  router: AnyRouter;
  createContext:
    ((opts: CreateExpressContextOptions) => Promise<T>) | undefined;
  verify: TokenVerifier;
  tokenHeader?: string;
  host?: string;
}) => {
  const trpcRouter = Router();
  trpcRouter.use(createExpressMiddleware({ router, createContext }));

  return runExpressApp(
    moduleName,
    { "/trpc": trpcRouter },
    [bearerAuthzMiddleware(verify, tokenHeader)],
    host
  );
};
