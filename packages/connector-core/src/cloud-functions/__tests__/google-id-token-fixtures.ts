/**
 * Shared by the tests for `runCloudRunConnector` and `runHttpConnector`. Each
 * test file mocks `runExpressApp`, so the helpers take the routes and
 * middlewares the runner handed it.
 */
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
import { vi } from "vitest";

import { createExpressApp } from "../../http/index.ts";
import { newMetadataRouter } from "../../metadata.ts";
import { newConnectorRouter, newConnectorTRPC } from "../../trpc.ts";

export const INVOKER = "invoker@p0-prod.iam.gserviceaccount.com";
export const AUDIENCE = "https://connector.example.com?p0_org=tenant-a";
export const OTHER_AUDIENCE = "https://connector.example.com?p0_org=tenant-b";
const KEY_ID = "test-key";

type CertsResponse = Awaited<
  ReturnType<OAuth2Client["getFederatedSignonCertsAsync"]>
>;

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

/** Mints an RS256 ID token shaped like Google's, signed with the test key. */
export const mintToken = (
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

/** Mints a token for the invoker that expired an hour ago. */
export const mintExpiredToken = (aud: string) => {
  const now = Math.floor(Date.now() / 1000);
  return mintToken({
    aud,
    email: INVOKER,
    iat: now - 2 * 3600,
    exp: now - 3600,
  });
};

/** Mints a token for the invoker signed with a key Google didn't publish. */
export const mintTokenWithBadSignature = (aud: string) => {
  const { privateKey: otherKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return mintToken({ aud, email: INVOKER }, otherKey);
};

/** Serves the test key in place of Google's published certificates. */
export const stubGoogleCerts = () =>
  vi
    .spyOn(OAuth2Client.prototype, "getFederatedSignonCertsAsync")
    .mockResolvedValue({
      certs: {
        [KEY_ID]: publicKey.export({ type: "spki", format: "pem" }).toString(),
      },
      format: "PEM" as CertsResponse["format"],
    });

/** Runs the middleware and resolves with whatever it passes to `next`. */
export const authorize = (middleware: RequestHandler, token: string) =>
  new Promise<unknown>((resolve) => {
    middleware(
      { headers: { authorization: `Bearer ${token}` } } as Request,
      {} as Response,
      resolve
    );
  });

const t = newConnectorTRPC();

export const emptyRouter = t.router({});

/** An `app` router with only the metadata procedures, at version 1.2.3. */
export const metadataAppRouter = newConnectorRouter(
  "app",
  t,
  {},
  t.router({}),
  newMetadataRouter(t, "1.2.3")
);

/** Serves `app` on a free local port for the length of `use`. */
const withServer = async <R>(
  app: express.Express,
  use: (baseUrl: string) => Promise<R>
) => {
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  try {
    const { port } = server.address() as AddressInfo;
    return await use(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
};

/** Fetches `app.metadata.get` from the runner's `/trpc` routes, past the bearer check. */
export const fetchMetadata = (routes: Record<string, Router>) =>
  withServer(express().use("/trpc", routes["/trpc"]!), async (baseUrl) => {
    const response = await fetch(`${baseUrl}/trpc/app.metadata.get`);
    const body = (await response.json()) as {
      result: { data: Record<string, unknown> };
    };
    return body.result.data;
  });

/** Fetches `GET /health` without a token from the app the runner would serve. */
export const fetchHealth = (
  moduleName: string,
  routes: Record<string, Router>,
  middlewares: RequestHandler[]
) =>
  withServer(
    createExpressApp(moduleName, routes, middlewares),
    async (baseUrl) => {
      const response = await fetch(`${baseUrl}/health`);
      return { status: response.status, body: await response.json() };
    }
  );
