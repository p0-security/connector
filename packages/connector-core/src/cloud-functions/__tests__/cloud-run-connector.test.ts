import type { Request, RequestHandler, Response } from "express";
import { OAuth2Client } from "google-auth-library";
import { generateKeyPairSync, sign } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type * as http from "../../http/index.ts";
import { runExpressApp } from "../../http/index.ts";
import { AuthError } from "../../http/types/error.ts";
import { newConnectorTRPC } from "../../trpc.ts";
import { runCloudRunConnector } from "../cloud-run-connector.ts";

// Keep the real bearer middleware; only stop the server from binding a port.
vi.mock("../../http/index.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof http>()),
  runExpressApp: vi.fn(),
}));

const INVOKER = "invoker@p0-prod.iam.gserviceaccount.com";
const AUDIENCE = "https://connector.example.com?p0_org=tenant-a";
const KEY_ID = "test-key";

type CertsResponse = Awaited<
  ReturnType<OAuth2Client["getFederatedSignonCertsAsync"]>
>;

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

/** Mints an RS256 ID token shaped like Google's, signed with the test key. */
const mintToken = (claims: { aud: string; email: string }) => {
  const now = Math.floor(Date.now() / 1000);
  const encode = (part: object) =>
    Buffer.from(JSON.stringify(part)).toString("base64url");
  const signed = `${encode({ alg: "RS256", kid: KEY_ID, typ: "JWT" })}.${encode(
    { iss: "https://accounts.google.com", iat: now, exp: now + 3600, ...claims }
  )}`;
  const signature = sign("RSA-SHA256", Buffer.from(signed), privateKey);
  return `${signed}.${signature.toString("base64url")}`;
};

const { router } = newConnectorTRPC();
const emptyRouter = router({});

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

beforeEach(() => {
  vi.stubEnv("INVOKER_SA_EMAIL", INVOKER);
  vi.stubEnv("CONNECTOR_AUDIENCE", AUDIENCE);
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
});

describe("runCloudRunConnector at startup", () => {
  it.each([
    ["INVOKER_SA_EMAIL", undefined],
    ["INVOKER_SA_EMAIL", ""],
    ["CONNECTOR_AUDIENCE", undefined],
    ["CONNECTOR_AUDIENCE", ""],
  ])("throws without serving when %s is %j", (name, value) => {
    vi.stubEnv(name, value);

    expect(() => runCloudRunConnector("test", emptyRouter)).toThrow(
      /is not set or present/
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
});

describe("the bearer check runCloudRunConnector serves", () => {
  it("admits a token for the invoker and the configured audience", async () => {
    const token = mintToken({ aud: AUDIENCE, email: INVOKER });

    await expect(authorize(startConnector(), token)).resolves.toBeUndefined();
  });

  it("rejects a token minted for another audience", async () => {
    // What P0 mints when another tenant registers this connector's URL.
    const token = mintToken({
      aud: "https://connector.example.com?p0_org=tenant-b",
      email: INVOKER,
    });

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
