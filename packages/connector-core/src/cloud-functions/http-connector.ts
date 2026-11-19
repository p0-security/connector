import type { AnyRouter } from "@trpc/server";
import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";

import { createLogger } from "../logger.ts";
import { newGoogleIdTokenVerifier } from "./google-id-token-connector.ts";
import { type TokenVerifier, serveTrpcConnector } from "./trpc-server.ts";

const logger = createLogger();

const AUTH_MODES = ["google-id-token", "gateway"] as const;

type ConnectorAuthMode = (typeof AUTH_MODES)[number];

const isConnectorAuthMode = (value: string): value is ConnectorAuthMode =>
  (AUTH_MODES as readonly string[]).includes(value);

/**
 * Reads `CONNECTOR_AUTH`, defaulting to `google-id-token` when it's unset.
 * Throws on any other value, including an empty or whitespace-padded one.
 */
const connectorAuthModeFromEnv = (): ConnectorAuthMode => {
  const mode = process.env.CONNECTOR_AUTH;
  if (mode === undefined) {
    return "google-id-token";
  }
  if (!isConnectorAuthMode(mode)) {
    throw new Error(
      `CONNECTOR_AUTH must be one of ${AUTH_MODES.map((m) => `"${m}"`).join(", ")}, with no surrounding whitespace`
    );
  }
  return mode;
};

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

/** Gateway mode's default bind address, so only the same host can connect. */
const GATEWAY_DEFAULT_BIND_ADDRESS = "127.0.0.1";

/**
 * Reads `CONNECTOR_BIND_ADDRESS`, defaulting to the loopback address when it's
 * unset. Throws when it's set but empty or whitespace-padded.
 */
const gatewayBindAddressFromEnv = (): string => {
  const address = process.env.CONNECTOR_BIND_ADDRESS;
  if (address === undefined) {
    return GATEWAY_DEFAULT_BIND_ADDRESS;
  }
  if (!address) {
    throw new Error("Connector bind address is set but empty");
  }
  if (address !== address.trim()) {
    throw new Error(
      "Connector bind address has leading or trailing whitespace"
    );
  }
  return address;
};

/** How a mode authenticates `/trpc` requests, and where it listens. */
type HttpConnectorAuth = {
  /**
   * Checks the bearer token on every `/trpc` request. `null` serves `/trpc`
   * without a check, for a mode that trusts a proxy in front of the server.
   */
  verify: TokenVerifier | null;
  /** Address to listen on. `undefined` listens on every interface. */
  host: string | undefined;
};

/**
 * Builds each mode's auth from the environment, throwing if it's
 * misconfigured. A mode that checks a token of its own supplies its `verify`
 * here; the runner doesn't change.
 */
const newHttpConnectorAuth: Record<ConnectorAuthMode, () => HttpConnectorAuth> =
  {
    "google-id-token": () => ({
      verify: newGoogleIdTokenVerifier(connectorAudienceFromEnv()),
      host: undefined,
    }),
    gateway: () => {
      const host = gatewayBindAddressFromEnv();
      logger.warn(
        { authMode: "gateway", bindAddress: host },
        `Auth mode is gateway: this connector does not authenticate requests and relies on the proxy in front of it. Listening on ${host}.`
      );
      return { verify: null, host };
    },
  };

/**
 * Creates a service, on any host, that exposes a tRPC router over Express at
 * `/trpc`.
 *
 * The server speaks plain HTTP on `$PORT` (default `8080`). `$CONNECTOR_AUTH`
 * picks how it authenticates requests:
 *
 * - `google-id-token` (the default when unset): requests must carry a
 *   Google-signed ID token whose `email` claim is `$INVOKER_SA_EMAIL` and whose
 *   `aud` claim is exactly `$CONNECTOR_AUDIENCE`. Nothing in front of the
 *   service checks the audience, so the runner always does. The server listens
 *   on every interface. Put it behind a load balancer, ingress or proxy that
 *   terminates TLS, so the bearer token is never sent unencrypted.
 * - `gateway`: the server checks no token and serves every `/trpc` request,
 *   with or without an `Authorization` header. It trusts a proxy on the same
 *   host to have authenticated each request, so nothing else may be able to
 *   reach its port. It listens on `127.0.0.1` unless `$CONNECTOR_BIND_ADDRESS`
 *   names another address. `INVOKER_SA_EMAIL` and `CONNECTOR_AUDIENCE` are
 *   ignored. It logs a warning at startup naming the mode and the address.
 *
 * Throws before binding a port if `CONNECTOR_AUTH` is set to anything else,
 * including an empty or whitespace-padded value. In `google-id-token` mode,
 * also throws if `INVOKER_SA_EMAIL` is unset or empty, or if
 * `CONNECTOR_AUDIENCE` is unset, empty, or has leading or trailing whitespace.
 * In `gateway` mode, also throws if `CONNECTOR_BIND_ADDRESS` is set but empty
 * or has leading or trailing whitespace.
 *
 * `GET /health` is served without a token in both modes, for load balancer
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
  const { verify, host } = newHttpConnectorAuth[connectorAuthModeFromEnv()]();
  return serveTrpcConnector(moduleName, router, createContext, verify, host);
};
