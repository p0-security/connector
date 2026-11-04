import type { AnyRouter } from "@trpc/server";
import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";

import {
  newGoogleIdTokenVerifier,
  serveGoogleIdTokenConnector,
} from "./google-id-token-connector.ts";

/**
 * Creates a Cloud Run service that exposes a tRPC router over Express at
 * `/trpc`, gated by bearer-token auth.
 *
 * Requests must carry a Google-signed ID token whose `email` claim is
 * `$INVOKER_SA_EMAIL`. The token's audience isn't checked: Cloud Run's own
 * invoker check is what turns away a token minted for another service, so the
 * service has to stay private. Off Cloud Run, use `runHttpConnector`. Throws
 * before binding a port if `INVOKER_SA_EMAIL` is unset or empty.
 *
 * `GET /health` is the one route served without a token, for load balancer
 * health checks. It returns `{ module: moduleName }`.
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
  const verify = newGoogleIdTokenVerifier();
  return serveGoogleIdTokenConnector(moduleName, router, createContext, verify);
};
