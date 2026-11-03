import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type * as http from "../../http/index.ts";
import { runExpressApp } from "../../http/index.ts";
import { AuthError } from "../../http/types/error.ts";
import type * as loggerModule from "../../logger.ts";
import { runCloudRunConnector } from "../cloud-run-connector.ts";
import {
  AUDIENCE,
  INVOKER,
  OTHER_AUDIENCE,
  authorize,
  emptyRouter,
  fetchHealth,
  fetchMetadata,
  metadataAppRouter,
  mintExpiredToken,
  mintToken,
  mintTokenWithBadSignature,
  stubGoogleCerts,
} from "./google-id-token-fixtures.ts";

// Keep the real bearer middleware; only stop the server from binding a port.
vi.mock("../../http/index.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof http>()),
  runExpressApp: vi.fn(),
}));

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const warn = vi.hoisted(() => vi.fn());

// Capture the runner's startup warnings.
vi.mock("../../logger.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof loggerModule>();
  return {
    ...actual,
    createLogger: (...args: Parameters<typeof actual.createLogger>) => {
      const logger = actual.createLogger(...args);
      logger.warn = warn;
      return logger;
    },
  };
});

/** Starts the connector and returns what it would serve. */
const start = (router = emptyRouter) => {
  runCloudRunConnector("test", router);
  const [, routes, middlewares] = vi.mocked(runExpressApp).mock.calls[0]!;
  return { routes, middlewares: middlewares! };
};

/** Starts the connector and returns the bearer middleware it would serve. */
const startConnector = () => start().middlewares[0]!;

/** Unsets the audience, on what looks like Cloud Run. */
const onCloudRunWithoutAudience = () => {
  vi.stubEnv("CONNECTOR_AUDIENCE", undefined);
  vi.stubEnv("K_SERVICE", "connector");
};

beforeEach(() => {
  vi.stubEnv("INVOKER_SA_EMAIL", INVOKER);
  vi.stubEnv("CONNECTOR_AUDIENCE", AUDIENCE);
  // Don't let the machine running the tests look like Cloud Run.
  vi.stubEnv("K_SERVICE", undefined);
  stubGoogleCerts();
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.mocked(runExpressApp).mockClear();
  warn.mockClear();
});

describe("runCloudRunConnector at startup", () => {
  it.each([undefined, ""])(
    "throws without serving when INVOKER_SA_EMAIL is %j",
    (value) => {
      vi.stubEnv("INVOKER_SA_EMAIL", value);

      expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
        /Invoker service account email is not set or present/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );

  it("throws without serving when CONNECTOR_AUDIENCE is empty", () => {
    vi.stubEnv("CONNECTOR_AUDIENCE", "");

    expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
      /Connector audience is not set or present/
    );
    expect(runExpressApp).not.toHaveBeenCalled();
  });

  it("throws without serving when CONNECTOR_AUDIENCE is empty, even on Cloud Run", () => {
    vi.stubEnv("CONNECTOR_AUDIENCE", "");
    vi.stubEnv("K_SERVICE", "connector");

    expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
      /Connector audience is not set or present/
    );
    expect(runExpressApp).not.toHaveBeenCalled();
  });

  it.each(["   ", ` ${AUDIENCE}`, `${AUDIENCE}\n`])(
    "throws without serving when CONNECTOR_AUDIENCE is %j",
    (value) => {
      vi.stubEnv("CONNECTOR_AUDIENCE", value);

      expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
        /leading or trailing whitespace/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );

  it.each([undefined, ""])(
    "throws without serving when CONNECTOR_AUDIENCE is unset and K_SERVICE is %j",
    (value) => {
      vi.stubEnv("CONNECTOR_AUDIENCE", undefined);
      vi.stubEnv("K_SERVICE", value);

      expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
        /K_SERVICE is not set/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );

  it("starts on Cloud Run without CONNECTOR_AUDIENCE, and warns that Cloud Run IAM is the only audience check", () => {
    onCloudRunWithoutAudience();

    runCloudRunConnector("test", emptyRouter);

    expect(runExpressApp).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      expect.stringMatching(/Cloud Run IAM is the only token audience check/)
    );
  });

  it("starts with CONNECTOR_AUDIENCE, without a warning", () => {
    runCloudRunConnector("test", emptyRouter);

    expect(runExpressApp).toHaveBeenCalledTimes(1);
    expect(warn).not.toHaveBeenCalled();
  });

  it("starts with CONNECTOR_AUDIENCE on Cloud Run, without a warning", () => {
    vi.stubEnv("K_SERVICE", "connector");

    runCloudRunConnector("test", emptyRouter);

    expect(runExpressApp).toHaveBeenCalledTimes(1);
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("the bearer check runCloudRunConnector serves", () => {
  describe("with CONNECTOR_AUDIENCE set", () => {
    it("admits a token for the invoker and the configured audience", async () => {
      const token = mintToken({ aud: AUDIENCE, email: INVOKER });

      await expect(authorize(startConnector(), token)).resolves.toBeUndefined();
    });

    it("rejects a token minted for another audience", async () => {
      // What P0 mints when another tenant registers this connector's URL.
      const token = mintToken({ aud: OTHER_AUDIENCE, email: INVOKER });

      await expect(authorize(startConnector(), token)).resolves.toBeInstanceOf(
        AuthError
      );
    });

    it("rejects a token minted for another audience on Cloud Run", async () => {
      vi.stubEnv("K_SERVICE", "connector");
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
  });

  describe("on Cloud Run without CONNECTOR_AUDIENCE", () => {
    beforeEach(onCloudRunWithoutAudience);

    it.each([AUDIENCE, OTHER_AUDIENCE, "https://anything.example.com"])(
      "admits a token for the invoker minted for %j",
      async (aud) => {
        const token = mintToken({ aud, email: INVOKER });

        await expect(
          authorize(startConnector(), token)
        ).resolves.toBeUndefined();
      }
    );

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
});

describe("app.metadata.get served by runCloudRunConnector", () => {
  it("reports audienceCheck: true with CONNECTOR_AUDIENCE set", async () => {
    await expect(
      fetchMetadata(start(metadataAppRouter).routes)
    ).resolves.toMatchObject({
      connectorVersion: "1.2.3",
      audienceCheck: true,
    });
  });

  it("reports audienceCheck: true with CONNECTOR_AUDIENCE set on Cloud Run", async () => {
    vi.stubEnv("K_SERVICE", "connector");

    await expect(
      fetchMetadata(start(metadataAppRouter).routes)
    ).resolves.toMatchObject({ audienceCheck: true });
  });

  it("reports audienceCheck: false on Cloud Run without CONNECTOR_AUDIENCE", async () => {
    onCloudRunWithoutAudience();

    await expect(
      fetchMetadata(start(metadataAppRouter).routes)
    ).resolves.toMatchObject({
      connectorVersion: "1.2.3",
      audienceCheck: false,
    });
  });
});

describe("GET /health served by runCloudRunConnector", () => {
  it("answers without a token", async () => {
    const { routes, middlewares } = start();

    await expect(fetchHealth("test", routes, middlewares)).resolves.toEqual({
      status: 200,
      body: { module: "test" },
    });
  });
});
