import type { AnyRouter } from "@trpc/server";
import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";

import {
  connectorAudienceFromEnv,
  serveGoogleIdTokenConnector,
} from "./google-id-token-connector.ts";

/**
 * Creates a Cloud Run service that exposes a tRPC router over Express at
 * `/trpc`, gated by bearer-token auth.
 *
 * Requests must carry a Google-signed ID token whose `email` claim is
 * `$INVOKER_SA_EMAIL`. The token's `aud` claim is checked as follows:
 *
 * - With `CONNECTOR_AUDIENCE` set, `aud` must equal it exactly.
 * - With it unset, `aud` isn't compared. Cloud Run IAM turns away a token
 *   minted for another service, so the service has to stay private.
 *
 * Off Cloud Run, use `runHttpConnector`, which always requires
 * `CONNECTOR_AUDIENCE`. `app.metadata.get` reports whether `aud` is compared
 * as `audienceCheck`.
 *
 * Throws before binding a port if `INVOKER_SA_EMAIL` is unset or empty, or if
 * `CONNECTOR_AUDIENCE` is empty or has leading or trailing whitespace.
 *
 * The context each procedure receives is a shallow copy of what
 * `createContext` returns (an empty object without one), with the audience
 * mode added under a private key.
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
) =>
  serveGoogleIdTokenConnector(
    moduleName,
    router,
    createContext,
    connectorAudienceFromEnv()
  );
