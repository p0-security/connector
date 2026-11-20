import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type * as http from "../../http/index.ts";
import { runExpressApp } from "../../http/index.ts";
import { AuthError } from "../../http/types/error.ts";
import { runHttpConnector } from "../http-connector.ts";
import {
  AUDIENCE,
  INVOKER,
  OTHER_AUDIENCE,
  authorize,
  emptyRouter,
  fetchHealth,
  fetchPing,
  mintExpiredToken,
  mintToken,
  mintTokenWithBadSignature,
  pingRouter,
  stubGoogleCerts,
} from "./google-id-token-fixtures.ts";

const { warn } = vi.hoisted(() => ({ warn: vi.fn() }));

// Capture the startup warning without printing it.
vi.mock("../../logger.ts", () => ({
  createLogger: () => ({ info: vi.fn(), warn, error: vi.fn() }),
}));

// Keep the real bearer middleware; only stop the server from binding a port.
vi.mock("../../http/index.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof http>()),
  runExpressApp: vi.fn(),
}));

/** Starts the connector and returns what it would serve. */
const start = () => {
  runHttpConnector("test", emptyRouter);
  const [, routes, middlewares] = vi.mocked(runExpressApp).mock.calls[0]!;
  return { routes, middlewares: middlewares! };
};

/** Starts the connector and returns the bearer middleware it would serve. */
const startConnector = () => start().middlewares[0]!;

beforeEach(() => {
  vi.stubEnv("INVOKER_SA_EMAIL", INVOKER);
  vi.stubEnv("CONNECTOR_AUDIENCE", AUDIENCE);
  stubGoogleCerts();
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.mocked(runExpressApp).mockClear();
  warn.mockClear();
});

describe("runHttpConnector at startup", () => {
  it.each([undefined, ""])(
    "throws without serving when INVOKER_SA_EMAIL is %j",
    (value) => {
      vi.stubEnv("INVOKER_SA_EMAIL", value);

      expect(() => runHttpConnector("test", emptyRouter)).toThrow(
        /Invoker service account email is not set or present/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );

  it.each([
    [undefined, /Connector audience is not set/],
    ["", /Connector audience is set but empty/],
  ])(
    "throws without serving when CONNECTOR_AUDIENCE is %j",
    (value, message) => {
      vi.stubEnv("CONNECTOR_AUDIENCE", value);

      expect(() => runHttpConnector("test", emptyRouter)).toThrow(message);
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );

  it.each(["   ", ` ${AUDIENCE}`, `${AUDIENCE}\n`])(
    "throws without serving when CONNECTOR_AUDIENCE is %j",
    (value) => {
      vi.stubEnv("CONNECTOR_AUDIENCE", value);

      expect(() => runHttpConnector("test", emptyRouter)).toThrow(
        /leading or trailing whitespace/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );

  it("starts with CONNECTOR_AUDIENCE, without the gateway warning", () => {
    runHttpConnector("test", emptyRouter);

    expect(runExpressApp).toHaveBeenCalledTimes(1);
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("the bearer check runHttpConnector serves", () => {
  it("admits a token for the invoker and the configured audience", async () => {
    const token = mintToken({ aud: AUDIENCE, email: INVOKER });

    await expect(authorize(startConnector(), token)).resolves.toBeUndefined();
  });

  it("rejects a token minted for another audience", async () => {
    const token = mintToken({ aud: OTHER_AUDIENCE, email: INVOKER });

    await expect(authorize(startConnector(), token)).resolves.toBeInstanceOf(
      AuthError
    );
  });

  it("rejects a token for another service account", async () => {
    const token = mintToken({
      aud: AUDIENCE,
      email: "someone-else@p0-prod.iam.gserviceaccount.com",
    });

    await expect(authorize(startConnector(), token)).resolves.toBeInstanceOf(
      AuthError
    );
  });

  it("rejects a token with a bad signature", async () => {
    const token = mintTokenWithBadSignature(AUDIENCE);

    await expect(authorize(startConnector(), token)).resolves.toBeInstanceOf(
      AuthError
    );
  });

  it("rejects an expired token", async () => {
    const token = mintExpiredToken(AUDIENCE);

    await expect(authorize(startConnector(), token)).resolves.toBeInstanceOf(
      AuthError
    );
  });
});

describe("GET /health served by runHttpConnector", () => {
  it("answers without a token", async () => {
    const { routes, middlewares } = start();

    await expect(fetchHealth("test", routes, middlewares)).resolves.toEqual({
      status: 200,
      body: { module: "test" },
    });
  });
});

/** Starts the connector on `pingRouter` and returns what it would serve. */
const startPing = () => {
  runHttpConnector("test", pingRouter);
  const [, routes, middlewares, host] = vi.mocked(runExpressApp).mock.calls[0]!;
  return { routes, middlewares: middlewares!, host };
};

describe("runHttpConnector with CONNECTOR_AUTH=google-id-token", () => {
  beforeEach(() => {
    vi.stubEnv("CONNECTOR_AUTH", "google-id-token");
  });

  it("refuses /trpc without an Authorization header", async () => {
    const { routes, middlewares, host } = startPing();

    expect(host).toBeUndefined();
    await expect(fetchPing(routes, middlewares)).resolves.toMatchObject({
      status: 403,
    });
  });
});

describe("runHttpConnector with an unknown CONNECTOR_AUTH", () => {
  it.each(["", "none"])(
    "throws without serving when CONNECTOR_AUTH is %j",
    (value) => {
      vi.stubEnv("CONNECTOR_AUTH", value);

      expect(() => runHttpConnector("test", emptyRouter)).toThrow(
        /CONNECTOR_AUTH must be "google-id-token" or "gateway"/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );
});

describe("runHttpConnector with CONNECTOR_AUTH=gateway", () => {
  beforeEach(() => {
    vi.stubEnv("CONNECTOR_AUTH", "gateway");
    vi.stubEnv("INVOKER_SA_EMAIL", undefined);
    vi.stubEnv("CONNECTOR_AUDIENCE", undefined);
  });

  it("serves /trpc without an Authorization header", async () => {
    const { routes, middlewares } = startPing();

    await expect(fetchPing(routes, middlewares)).resolves.toEqual({
      status: 200,
      body: { result: { data: "pong" } },
    });
  });

  it("listens on 127.0.0.1 by default", () => {
    expect(startPing().host).toBe("127.0.0.1");
  });

  it("warns once at startup that it doesn't authenticate, naming the address", () => {
    vi.stubEnv("CONNECTOR_BIND_ADDRESS", "10.0.0.5");

    expect(startPing().host).toBe("10.0.0.5");
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      { authMode: "gateway", bindAddress: "10.0.0.5" },
      expect.stringMatching(
        /does not authenticate requests and relies on the proxy in front of it.*10\.0\.0\.5/
      )
    );
  });
});
