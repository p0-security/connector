import type { AnyRouter } from "@trpc/server";
import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";
import { isIP, isIPv4 } from "node:net";

import type { TokenVerifier } from "../http/middlewares/bearer.ts";
import { createLogger } from "../logger.ts";
import { newGoogleIdTokenVerifier } from "./google-id-token-connector.ts";
import {
  identityKeysFromJwks,
  newP0IdentityTokenVerifier,
} from "./p0-identity-token.ts";
import { serveTrpcConnector } from "./trpc-server.ts";

const logger = createLogger();

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
 * Reads `CONNECTOR_BIND_ADDRESS`, or `undefined` when it's unset or empty.
 * Throws unless it's an IP address, so a host name such as `localhost` can't
 * make the connector listen somewhere other than the proxy expects.
 */
const bindAddressFromEnv = (): string | undefined => {
  const value = process.env.CONNECTOR_BIND_ADDRESS;
  if (!value) {
    return undefined;
  }
  if (isIP(value) === 0) {
    throw new Error(
      `CONNECTOR_BIND_ADDRESS must be an IP address, not ${JSON.stringify(value)}`
    );
  }
  return value;
};

const isLoopback = (host: string) =>
  host === "::1" || (isIPv4(host) && host.startsWith("127."));

/** How the server checks requests and where it listens. */
type AuthOptions = {
  verify: TokenVerifier;
  tokenHeader?: string;
  host?: string;
};

/**
 * Each `CONNECTOR_AUTH` mode, reading the environment it needs. The README
 * documents the modes and their variables.
 */
const authModes = {
  "google-id-token": (bindAddress?: string): AuthOptions => ({
    verify: newGoogleIdTokenVerifier(connectorAudienceFromEnv()),
    host: bindAddress,
  }),
  "trusted-proxy": (bindAddress = "127.0.0.1"): AuthOptions => {
    const audience = connectorAudienceFromEnv();
    const keys = identityKeysFromJwks(process.env.CONNECTOR_IDENTITY_JWKS);
    logger.info(
      {
        authMode: "trusted-proxy",
        bindAddress,
        identityKeyIds: [...keys.keys()],
      },
      `Auth mode is trusted-proxy: requests need P0's identity token in X-P0-Authorization. Listening on ${bindAddress}; point the proxy at this address, not at "localhost".`
    );
    if (!isLoopback(bindAddress)) {
      logger.warn(
        { bindAddress },
        `CONNECTOR_BIND_ADDRESS ${bindAddress} is not 127.x.x.x or ::1, so callers other than the proxy may be able to reach the connector.`
      );
    }
    return {
      verify: newP0IdentityTokenVerifier({ audience, keys }),
      tokenHeader: "x-p0-authorization",
      host: bindAddress,
    };
  },
};

/**
 * Reads the server's whole configuration from the environment. Throws if any
 * of it is missing or invalid.
 */
const authOptionsFromEnv = (): AuthOptions => {
  const mode = process.env.CONNECTOR_AUTH ?? "google-id-token";
  const modes = Object.keys(authModes);
  if (!modes.includes(mode)) {
    throw new Error(`CONNECTOR_AUTH must be one of: ${modes.join(", ")}`);
  }
  return authModes[mode as keyof typeof authModes](bindAddressFromEnv());
};

/**
 * Creates a service, on any host, that exposes a tRPC router over Express at
 * `/trpc`, gated by bearer-token auth.
 *
 * The server speaks plain HTTP on `$PORT` (default `8080`). Put it behind a
 * load balancer, ingress or proxy that terminates TLS, so the bearer token is
 * never sent unencrypted.
 *
 * By default (`CONNECTOR_AUTH=google-id-token`), requests must carry a
 * Google-signed ID token whose `email` claim is `$INVOKER_SA_EMAIL` and whose
 * `aud` claim is exactly `$CONNECTOR_AUDIENCE`. Nothing in front of the
 * service checks the audience, so the runner always does.
 *
 * With `CONNECTOR_AUTH=trusted-proxy`, for a connector behind a proxy that
 * authenticates P0 itself, requests must instead carry P0's identity token in
 * `X-P0-Authorization`, verified against `$CONNECTOR_IDENTITY_JWKS`. The
 * connector SDK README describes both modes and their variables.
 *
 * Throws before binding a port if `CONNECTOR_AUTH` or `CONNECTOR_BIND_ADDRESS`
 * is invalid, or if a variable the mode needs is missing or invalid.
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
  const options = authOptionsFromEnv();
  return serveTrpcConnector({ moduleName, router, createContext, ...options });
};
