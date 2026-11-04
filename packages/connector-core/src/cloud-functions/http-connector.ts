import type { AnyRouter } from "@trpc/server";
import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";

import {
  newGoogleIdTokenVerifier,
  serveGoogleIdTokenConnector,
} from "./google-id-token-connector.ts";

/**
 * Reads `CONNECTOR_AUDIENCE`, throwing when it's unset or set to a value that
 * would reject every token.
 */
const connectorAudienceFromEnv = (): string => {
  const audience = process.env.CONNECTOR_AUDIENCE;
  if (audience === undefined) {
    throw new Error("Connector audience is not set");
  }
  // google-auth-library compares the audience whenever one is passed, so an
  // empty string would reject every token. Surrounding whitespace (say, a
  // trailing newline from a secret) would do the same. Refuse it rather than
  // trim it, since the value must match what P0 mints.
  if (!audience) {
    throw new Error("Connector audience is set but empty");
  }
  if (audience !== audience.trim()) {
    throw new Error("Connector audience has leading or trailing whitespace");
  }
  return audience;
};

/**
 * Creates a service, on any host, that exposes a tRPC router over Express at
 * `/trpc`, gated by bearer-token auth.
 *
 * The server speaks plain HTTP on `$PORT` (default `8080`). Put it behind a
 * load balancer, ingress or proxy that terminates TLS, so the bearer token is
 * never sent unencrypted.
 *
 * Requests must carry a Google-signed ID token whose `email` claim is
 * `$INVOKER_SA_EMAIL` and whose `aud` claim is exactly `$CONNECTOR_AUDIENCE`.
 * Nothing in front of the service checks the audience, so the runner always
 * does.
 *
 * Throws before binding a port if `INVOKER_SA_EMAIL` is unset or empty, or if
 * `CONNECTOR_AUDIENCE` is unset, empty, or has leading or trailing whitespace.
 *
 * `GET /health` is the one route served without a token, for load balancer
 * health checks. It returns `{ module: moduleName }`.
 * @summary Creates a service that exposes a tRPC router over Express.
 * @category Cloud Functions
 *
 * @param moduleName Name reported by `/health` and used in logs.
 * @param router The tRPC router to mount.
 * @param createContext Optional context factory; receives the Express adapter's options.
 */
export const runHttpConnector = <T>(
  moduleName: string,
  router: AnyRouter,
  createContext?: (opts: CreateExpressContextOptions) => Promise<T>
) => {
  // Read the environment before serving, so a misconfigured connector fails to
  // start rather than answering every request with a 403.
  const verify = newGoogleIdTokenVerifier(connectorAudienceFromEnv());
  return serveGoogleIdTokenConnector(moduleName, router, createContext, verify);
};
