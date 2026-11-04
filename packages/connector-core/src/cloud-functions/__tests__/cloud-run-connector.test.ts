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

beforeEach(() => {
  vi.stubEnv("INVOKER_SA_EMAIL", INVOKER);
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

  it.each([undefined, "", " padded "])(
    "ignores CONNECTOR_AUDIENCE when it's %j",
    (value) => {
      vi.stubEnv("CONNECTOR_AUDIENCE", value);

      runCloudRunConnector("test", emptyRouter);

      expect(runExpressApp).toHaveBeenCalledTimes(1);
    }
  );
});

describe("the bearer check runCloudRunConnector serves", () => {
  it.each([AUDIENCE, OTHER_AUDIENCE, "https://anything.example.com"])(
    "admits a token for the invoker minted for %j",
    async (aud) => {
      // Cloud Run IAM, not the connector, turns away other audiences.
      vi.stubEnv("CONNECTOR_AUDIENCE", AUDIENCE);
      const token = mintToken({ aud, email: INVOKER });

      await expect(authorize(startConnector(), token)).resolves.toBeUndefined();
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

describe("app.metadata.get served by runCloudRunConnector", () => {
  it("doesn't report audienceCheck", async () => {
    const metadata = await fetchMetadata(start(metadataAppRouter).routes);

    expect(metadata).toMatchObject({ connectorVersion: "1.2.3" });
    expect(metadata).not.toHaveProperty("audienceCheck");
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
