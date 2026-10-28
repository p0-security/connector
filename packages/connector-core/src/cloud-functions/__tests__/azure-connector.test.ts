import { initTRPC } from "@trpc/server";
import type { Request, RequestHandler, Response } from "express";
import jwt from "jsonwebtoken";
import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type * as http from "../../http/index.ts";
import { runAzureConnector } from "../azure-connector.ts";
import { entraIssuer } from "../entra-token.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const runExpressApp = vi.hoisted(() => vi.fn<typeof http.runExpressApp>());

// Stops the server from listening; the tests call its middleware directly.
vi.mock("../../http/index.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof http>()),
  runExpressApp,
}));

const TENANT_ID = "11111111-1111-1111-1111-111111111111";
const CLIENT_ID = "22222222-2222-2222-2222-222222222222";
const KID = "test-key";

const signingKey = generateKeyPairSync("rsa", { modulusLength: 2048 });

const router = initTRPC.create().router({});

const runAndGetMiddlewares = () => {
  runAzureConnector("test connector", router);
  expect(runExpressApp).toHaveBeenCalledTimes(1);
  return runExpressApp.mock.calls[0]?.[2] ?? [];
};

// Runs a middleware against a request with these headers and resolves with
// whatever it passes to `next`.
const callMiddleware = (
  middleware: RequestHandler,
  headers: Record<string, string>
) =>
  new Promise<unknown>((resolve) => {
    void middleware({ headers } as Request, {} as Response, (err?: unknown) =>
      resolve(err)
    );
  });

describe("runAzureConnector", () => {
  beforeEach(() => {
    vi.stubEnv("P0_INVOKER_TENANT_ID", TENANT_ID);
    vi.stubEnv("P0_INVOKER_CLIENT_ID", CLIENT_ID);
    vi.stubGlobal("fetch", async () =>
      Response.json({
        keys: [
          {
            ...signingKey.publicKey.export({ format: "jwk" }),
            kid: KID,
            use: "sig",
          },
        ],
      })
    );
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    runExpressApp.mockReset();
  });

  it("serves the router at /trpc", () => {
    runAzureConnector("test connector", router);
    expect(runExpressApp).toHaveBeenCalledWith(
      "test connector",
      { "/trpc": expect.any(Function) },
      [expect.any(Function)]
    );
  });

  it.each(["P0_INVOKER_TENANT_ID", "P0_INVOKER_CLIENT_ID"])(
    "refuses to start without %s",
    (name) => {
      vi.stubEnv(name, "");
      expect(() => runAzureConnector("test connector", router)).toThrow(name);
      expect(runExpressApp).not.toHaveBeenCalled();
    }
  );

  it("ignores SKIP_VERIFY_TOKEN", () => {
    vi.stubEnv("SKIP_VERIFY_TOKEN", "true");
    vi.stubEnv("P0_INVOKER_TENANT_ID", "");
    expect(() => runAzureConnector("test connector", router)).toThrow(
      "P0_INVOKER_TENANT_ID"
    );
  });

  it("passes a request with a valid token", async () => {
    const [middleware] = runAndGetMiddlewares();
    const token = jwt.sign(
      { iss: entraIssuer(TENANT_ID), aud: CLIENT_ID, azp: CLIENT_ID },
      signingKey.privateKey,
      { algorithm: "RS256", keyid: KID, expiresIn: 3600 }
    );
    await expect(
      callMiddleware(middleware!, { authorization: `Bearer ${token}` })
    ).resolves.toBeUndefined();
  });

  it("rejects a request with no Authorization header", async () => {
    const [middleware] = runAndGetMiddlewares();
    await expect(callMiddleware(middleware!, {})).resolves.toMatchObject({
      type: "auth",
    });
  });

  it("rejects a request that has only Easy Auth's principal headers", async () => {
    const [middleware] = runAndGetMiddlewares();
    await expect(
      callMiddleware(middleware!, {
        "x-ms-client-principal-id": CLIENT_ID,
        "x-ms-client-principal-idp": "aad",
        "x-ms-client-principal": Buffer.from(
          JSON.stringify({ auth_typ: "aad", claims: [] })
        ).toString("base64"),
      })
    ).resolves.toMatchObject({ type: "auth" });
  });
});
