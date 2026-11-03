import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type * as http from "../../http/index.ts";
import { runExpressApp } from "../../http/index.ts";
import { AuthError } from "../../http/types/error.ts";
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

/** Starts the connector and returns what it would serve. */
const start = (router = emptyRouter) => {
  runCloudRunConnector("test", router);
  const [, routes, middlewares] = vi.mocked(runExpressApp).mock.calls[0]!;
  return { routes, middlewares: middlewares! };
};

/** Starts the connector and returns the bearer middleware it would serve. */
const startConnector = () => start().middlewares[0]!;

const withoutAudience = () => {
  vi.stubEnv("CONNECTOR_AUDIENCE", undefined);
};

beforeEach(() => {
  vi.stubEnv("INVOKER_SA_EMAIL", INVOKER);
  vi.stubEnv("CONNECTOR_AUDIENCE", AUDIENCE);
  stubGoogleCerts();
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.mocked(runExpressApp).mockClear();
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
      /Connector audience is set but empty/
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

  it("starts with CONNECTOR_AUDIENCE", () => {
    runCloudRunConnector("test", emptyRouter);

    expect(runExpressApp).toHaveBeenCalledTimes(1);
  });

  it("starts without CONNECTOR_AUDIENCE", () => {
    withoutAudience();

    runCloudRunConnector("test", emptyRouter);

    expect(runExpressApp).toHaveBeenCalledTimes(1);
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

  describe("without CONNECTOR_AUDIENCE", () => {
    beforeEach(withoutAudience);

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

  it("reports audienceCheck: false without CONNECTOR_AUDIENCE", async () => {
    withoutAudience();

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
