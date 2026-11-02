import express, {
  type Request,
  type RequestHandler,
  type Response,
  type Router,
} from "express";
import { OAuth2Client } from "google-auth-library";
import { type KeyObject, generateKeyPairSync, sign } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type * as http from "../../http/index.ts";
import { runExpressApp } from "../../http/index.ts";
import { AuthError } from "../../http/types/error.ts";
import type * as loggerModule from "../../logger.ts";
import { newMetadataRouter } from "../../metadata.ts";
import { newConnectorRouter, newConnectorTRPC } from "../../trpc.ts";
import { runCloudRunConnector } from "../cloud-run-connector.ts";

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

const INVOKER = "invoker@p0-prod.iam.gserviceaccount.com";
const AUDIENCE = "https://connector.example.com?p0_org=tenant-a";
const OTHER_AUDIENCE = "https://connector.example.com?p0_org=tenant-b";
const KEY_ID = "test-key";

type CertsResponse = Awaited<
  ReturnType<OAuth2Client["getFederatedSignonCertsAsync"]>
>;

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

/** Mints an RS256 ID token shaped like Google's, signed with the test key. */
const mintToken = (
  claims: { aud: string; email: string; iat?: number; exp?: number },
  signingKey: KeyObject = privateKey
) => {
  const now = Math.floor(Date.now() / 1000);
  const encode = (part: object) =>
    Buffer.from(JSON.stringify(part)).toString("base64url");
  const signed = `${encode({ alg: "RS256", kid: KEY_ID, typ: "JWT" })}.${encode(
    { iss: "https://accounts.google.com", iat: now, exp: now + 3600, ...claims }
  )}`;
  const signature = sign("RSA-SHA256", Buffer.from(signed), signingKey);
  return `${signed}.${signature.toString("base64url")}`;
};

const t = newConnectorTRPC();
const emptyRouter = t.router({});

/** Starts the connector and returns the bearer middleware it would serve. */
const startConnector = () => {
  runCloudRunConnector("test", emptyRouter);
  const [, , middlewares] = vi.mocked(runExpressApp).mock.calls[0]!;
  return middlewares![0]!;
};

/** Runs the middleware and resolves with whatever it passes to `next`. */
const authorize = (middleware: RequestHandler, token: string) =>
  new Promise<unknown>((resolve) => {
    middleware(
      { headers: { authorization: `Bearer ${token}` } } as Request,
      {} as Response,
      resolve
    );
  });

/** Sets the opt-out, without an audience, on what looks like Cloud Run. */
const optOutOnCloudRun = () => {
  vi.stubEnv("CONNECTOR_AUDIENCE", undefined);
  vi.stubEnv("CONNECTOR_AUDIENCE_CHECK", "cloud-run-iam");
  vi.stubEnv("K_SERVICE", "connector");
};

beforeEach(() => {
  vi.stubEnv("INVOKER_SA_EMAIL", INVOKER);
  vi.stubEnv("CONNECTOR_AUDIENCE", AUDIENCE);
  // Don't let the machine running the tests pick the mode.
  vi.stubEnv("CONNECTOR_AUDIENCE_CHECK", undefined);
  vi.stubEnv("K_SERVICE", undefined);
  // Serve the test key in place of Google's published certificates.
  vi.spyOn(
    OAuth2Client.prototype,
    "getFederatedSignonCertsAsync"
  ).mockResolvedValue({
    certs: {
      [KEY_ID]: publicKey.export({ type: "spki", format: "pem" }).toString(),
    },
    format: "PEM" as CertsResponse["format"],
  });
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

  it.each([undefined, ""])(
    "throws without serving when CONNECTOR_AUDIENCE is %j and there's no opt-out",
    (value) => {
      vi.stubEnv("CONNECTOR_AUDIENCE", value);

      expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
        /Connector audience is not set or present/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );

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

  it("throws without serving on Cloud Run with no audience and no opt-out", () => {
    // K_SERVICE on its own never turns the check off.
    vi.stubEnv("CONNECTOR_AUDIENCE", undefined);
    vi.stubEnv("K_SERVICE", "connector");

    expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
      /Connector audience is not set or present/
    );
    expect(runExpressApp).not.toHaveBeenCalled();
  });

  it.each([undefined, ""])(
    "throws without serving when the opt-out is set and K_SERVICE is %j",
    (value) => {
      optOutOnCloudRun();
      vi.stubEnv("K_SERVICE", value);

      expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
        /only allowed on Cloud Run/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );

  it.each(["", "off", "none", "CLOUD-RUN-IAM", " cloud-run-iam"])(
    "throws without serving when CONNECTOR_AUDIENCE_CHECK is %j",
    (value) => {
      vi.stubEnv("CONNECTOR_AUDIENCE_CHECK", value);

      expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
        /CONNECTOR_AUDIENCE_CHECK must be unset or "cloud-run-iam"/
      );
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );

  it("throws on an unknown CONNECTOR_AUDIENCE_CHECK on Cloud Run with no audience", () => {
    optOutOnCloudRun();
    vi.stubEnv("CONNECTOR_AUDIENCE_CHECK", "disabled");

    expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
      /CONNECTOR_AUDIENCE_CHECK must be unset or "cloud-run-iam"/
    );
    expect(runExpressApp).not.toHaveBeenCalled();
  });

  it("throws on an empty CONNECTOR_AUDIENCE even with the opt-out on Cloud Run", () => {
    optOutOnCloudRun();
    vi.stubEnv("CONNECTOR_AUDIENCE", "");

    expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
      /Connector audience is not set or present/
    );
    expect(runExpressApp).not.toHaveBeenCalled();
  });

  it("starts with the opt-out on Cloud Run, and warns that the check is off", () => {
    optOutOnCloudRun();

    runCloudRunConnector("test", emptyRouter);

    expect(runExpressApp).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      expect.stringMatching(/audience check is off/)
    );
  });

  it("starts with the audience, and warns that the opt-out is ignored", () => {
    vi.stubEnv("CONNECTOR_AUDIENCE_CHECK", "cloud-run-iam");
    vi.stubEnv("K_SERVICE", "connector");

    runCloudRunConnector("test", emptyRouter);

    expect(runExpressApp).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      expect.stringMatching(/Ignoring CONNECTOR_AUDIENCE_CHECK/)
    );
  });

  it("starts with the audience alone, without a warning", () => {
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

  describe("with CONNECTOR_AUDIENCE and the opt-out both set", () => {
    it("still rejects a token minted for another audience", async () => {
      vi.stubEnv("CONNECTOR_AUDIENCE_CHECK", "cloud-run-iam");
      vi.stubEnv("K_SERVICE", "connector");
      const token = mintToken({ aud: OTHER_AUDIENCE, email: INVOKER });

      await expect(authorize(startConnector(), token)).resolves.toBeInstanceOf(
        AuthError
      );
    });
  });

  describe("with the opt-out on Cloud Run", () => {
    beforeEach(optOutOnCloudRun);

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
      const { privateKey: otherKey } = generateKeyPairSync("rsa", {
        modulusLength: 2048,
      });
      const token = mintToken({ aud: AUDIENCE, email: INVOKER }, otherKey);

      await expect(authorize(startConnector(), token)).resolves.toBeInstanceOf(
        AuthError
      );
    });

    it("rejects an expired token", async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = mintToken({
        aud: AUDIENCE,
        email: INVOKER,
        iat: now - 2 * 3600,
        exp: now - 3600,
      });

      await expect(authorize(startConnector(), token)).resolves.toBeInstanceOf(
        AuthError
      );
    });
  });
});

describe("app.metadata.get served by runCloudRunConnector", () => {
  const appRouter = newConnectorRouter(
    "app",
    t,
    {},
    t.router({}),
    newMetadataRouter(t, "1.2.3")
  );

  /** Starts the connector and fetches its metadata, past the bearer check. */
  const fetchMetadata = async () => {
    runCloudRunConnector("test", appRouter);
    const [, routes] = vi.mocked(runExpressApp).mock.calls[0]!;
    const app = express().use("/trpc", routes["/trpc"] as Router);
    const server = await new Promise<Server>((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    try {
      const { port } = server.address() as AddressInfo;
      const response = await fetch(
        `http://127.0.0.1:${port}/trpc/app.metadata.get`
      );
      const body = (await response.json()) as {
        result: { data: Record<string, unknown> };
      };
      return body.result.data;
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  };

  it("reports audienceCheck: true with CONNECTOR_AUDIENCE set", async () => {
    await expect(fetchMetadata()).resolves.toMatchObject({
      connectorVersion: "1.2.3",
      audienceCheck: true,
    });
  });

  it("reports audienceCheck: true with CONNECTOR_AUDIENCE and the opt-out set", async () => {
    vi.stubEnv("CONNECTOR_AUDIENCE_CHECK", "cloud-run-iam");
    vi.stubEnv("K_SERVICE", "connector");

    await expect(fetchMetadata()).resolves.toMatchObject({
      audienceCheck: true,
    });
  });

  it("reports audienceCheck: false with the opt-out on Cloud Run", async () => {
    optOutOnCloudRun();

    await expect(fetchMetadata()).resolves.toMatchObject({
      connectorVersion: "1.2.3",
      audienceCheck: false,
    });
  });
});
