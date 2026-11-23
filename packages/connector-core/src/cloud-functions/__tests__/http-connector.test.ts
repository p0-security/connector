import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type * as http from "../../http/index.ts";
import { runExpressApp } from "../../http/index.ts";
import { AuthError } from "../../http/types/error.ts";
import { newGoogleIdTokenVerifier } from "../google-id-token-connector.ts";
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
import {
  IDENTITY_AUDIENCE,
  IDENTITY_JWKS,
  signIdentityToken,
} from "./p0-identity-token-fixtures.ts";

const { info, warn } = vi.hoisted(() => ({ info: vi.fn(), warn: vi.fn() }));

// Capture the startup log lines without printing them.
vi.mock("../../logger.ts", () => ({
  createLogger: () => ({ info, warn, error: vi.fn() }),
}));

const { logError } = vi.hoisted(() => ({ logError: vi.fn() }));

// Capture what the error handler logs for each refused request.
vi.mock("pino", () => ({
  pino: () => ({ error: logError, info: vi.fn(), warn: vi.fn() }),
}));

/** The 403 body for every refused request, in either mode. */
const REFUSED_BODY = {
  error: {
    message: "Unauthorized",
    publicMessage: "P0 could not properly identify you.",
  },
};

/** Everything the error handler has logged, as it would be written. */
const loggedErrors = () => JSON.stringify(logError.mock.calls);

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
  info.mockClear();
  warn.mockClear();
  logError.mockClear();
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

  it.each(["localhost", "connector.internal", "127.0.0.1 "])(
    "throws without serving when CONNECTOR_BIND_ADDRESS is %j",
    (value) => {
      vi.stubEnv("CONNECTOR_BIND_ADDRESS", value);

      expect(() => runHttpConnector("test", emptyRouter)).toThrow(
        /CONNECTOR_BIND_ADDRESS must be an IP address/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );

  it("starts with CONNECTOR_AUDIENCE, without a warning", () => {
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

  it("keeps a refused token out of the error, the log and the response", async () => {
    const token = mintTokenWithBadSignature(AUDIENCE);
    // google-auth-library's own error quotes the token.
    await expect(newGoogleIdTokenVerifier(AUDIENCE)(token)).rejects.toThrow(
      token
    );
    const { routes, middlewares } = start();

    const error = (await authorize(middlewares[0]!, token)) as AuthError;
    const response = await fetchPing(routes, middlewares, {
      Authorization: `Bearer ${token}`,
    });

    expect(error).toBeInstanceOf(AuthError);
    expect(String(error.cause)).toBe("Error: Token verification failed");
    expect(JSON.stringify(error)).not.toContain(token);
    expect(error.message).not.toContain(token);
    expect(error.stack).not.toContain(token);
    expect(response).toEqual({ status: 403, body: REFUSED_BODY });
    expect(loggedErrors()).toContain("Token verification failed");
    expect(loggedErrors()).not.toContain(token);
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

  it("refuses /trpc without an Authorization header, logging why", async () => {
    const { routes, middlewares } = startPing();

    await expect(fetchPing(routes, middlewares)).resolves.toEqual({
      status: 403,
      body: REFUSED_BODY,
    });
    expect(loggedErrors()).toContain("No authorization header");
  });

  it("listens on every interface by default", () => {
    expect(startPing().host).toBeUndefined();
  });

  it("listens on CONNECTOR_BIND_ADDRESS when it's set, without a warning", () => {
    vi.stubEnv("CONNECTOR_BIND_ADDRESS", "10.0.0.5");

    expect(startPing().host).toBe("10.0.0.5");
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("runHttpConnector with an unknown CONNECTOR_AUTH", () => {
  it.each(["", "none"])(
    "throws without serving when CONNECTOR_AUTH is %j",
    (value) => {
      vi.stubEnv("CONNECTOR_AUTH", value);

      expect(() => runHttpConnector("test", emptyRouter)).toThrow(
        "CONNECTOR_AUTH must be one of: google-id-token, trusted-proxy"
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );
});

describe("runHttpConnector with CONNECTOR_AUTH=trusted-proxy", () => {
  beforeEach(() => {
    vi.stubEnv("CONNECTOR_AUTH", "trusted-proxy");
    vi.stubEnv("INVOKER_SA_EMAIL", undefined);
    vi.stubEnv("CONNECTOR_AUDIENCE", IDENTITY_AUDIENCE);
    vi.stubEnv("CONNECTOR_IDENTITY_JWKS", IDENTITY_JWKS);
  });

  describe("at startup", () => {
    it.each([
      [undefined, /Connector audience is not set/],
      ["", /Connector audience is set but empty/],
      [`${IDENTITY_AUDIENCE}\n`, /leading or trailing whitespace/],
    ])(
      "throws without serving when CONNECTOR_AUDIENCE is %j",
      (value, message) => {
        vi.stubEnv("CONNECTOR_AUDIENCE", value);

        expect(() => runHttpConnector("test", emptyRouter)).toThrow(message);
        expect(runExpressApp).not.toHaveBeenCalled();
      }
    );

    it("throws without serving when CONNECTOR_IDENTITY_JWKS is invalid", () => {
      vi.stubEnv("CONNECTOR_IDENTITY_JWKS", "not json");

      expect(() => runHttpConnector("test", emptyRouter)).toThrow(
        /CONNECTOR_IDENTITY_JWKS is not JSON/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    });

    it("throws without serving or logging when CONNECTOR_BIND_ADDRESS is localhost", () => {
      vi.stubEnv("CONNECTOR_BIND_ADDRESS", "localhost");

      expect(() => runHttpConnector("test", emptyRouter)).toThrow(
        /CONNECTOR_BIND_ADDRESS must be an IP address/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
      expect(info).not.toHaveBeenCalled();
    });

    it("listens on 127.0.0.1 by default and logs the mode, address and key IDs", () => {
      expect(startPing().host).toBe("127.0.0.1");
      expect(info).toHaveBeenCalledWith(
        {
          authMode: "trusted-proxy",
          bindAddress: "127.0.0.1",
          identityKeyIds: ["key-a", "key-b"],
        },
        expect.stringContaining('not at "localhost"')
      );
      expect(warn).not.toHaveBeenCalled();
    });

    it.each(["127.0.0.2", "::1"])(
      "listens on the loopback address %j without a warning",
      (address) => {
        vi.stubEnv("CONNECTOR_BIND_ADDRESS", address);

        expect(startPing().host).toBe(address);
        expect(warn).not.toHaveBeenCalled();
      }
    );

    it("listens on a non-loopback address with a warning", () => {
      vi.stubEnv("CONNECTOR_BIND_ADDRESS", "10.0.0.5");

      expect(startPing().host).toBe("10.0.0.5");
      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn).toHaveBeenCalledWith(
        { bindAddress: "10.0.0.5" },
        expect.stringMatching(/10\.0\.0\.5 is not 127\.x\.x\.x or ::1/)
      );
    });
  });

  describe("on /trpc", () => {
    const ping = (headers: HeadersInit) => {
      const { routes, middlewares } = startPing();
      return fetchPing(routes, middlewares, headers);
    };

    it("serves a valid identity token in X-P0-Authorization", async () => {
      await expect(
        ping({ "X-P0-Authorization": `Bearer ${signIdentityToken()}` })
      ).resolves.toEqual({ status: 200, body: { result: { data: "pong" } } });
    });

    it("serves while the proxy sends its own Authorization header", async () => {
      await expect(
        ping({
          Authorization: "Bearer proxy-credential",
          "X-P0-Authorization": `Bearer ${signIdentityToken()}`,
        })
      ).resolves.toMatchObject({ status: 200 });
    });

    it.each([
      ["no header", {}, /No x-p0-authorization header/],
      [
        "the token only in Authorization",
        { Authorization: `Bearer ${signIdentityToken()}` },
        /No x-p0-authorization header/,
      ],
      [
        "a value that is not a bearer token",
        { "X-P0-Authorization": `Basic ${signIdentityToken()}` },
        /not a bearer token/,
      ],
      [
        "a token for another audience",
        {
          "X-P0-Authorization": `Bearer ${signIdentityToken({ aud: AUDIENCE })}`,
        },
        /wrong aud/,
      ],
      [
        "two X-P0-Authorization headers",
        [
          ["X-P0-Authorization", `Bearer ${signIdentityToken()}`],
          ["X-P0-Authorization", `Bearer ${signIdentityToken()}`],
        ],
        /not a bearer token/,
      ],
    ] satisfies [string, HeadersInit, RegExp][])(
      "refuses %s with a 403, logging the failed check",
      async (_name, headers, check) => {
        const response = await ping(headers);

        expect(response).toEqual({ status: 403, body: REFUSED_BODY });
        expect(loggedErrors()).toMatch(check);
        // A JWT starts with "eyJ", the encoding of '{"'.
        expect(loggedErrors()).not.toContain("eyJ");
      }
    );
  });

  it("answers GET /health without a token", async () => {
    const { routes, middlewares } = startPing();

    await expect(fetchHealth("test", routes, middlewares)).resolves.toEqual({
      status: 200,
      body: { module: "test" },
    });
  });
});
