import jwt from "jsonwebtoken";
import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { bearerAuthzMiddleware } from "../../http/index.ts";
import { TokenRefusal } from "../../http/middlewares/bearer.ts";
import { AuthError } from "../../http/types/error.ts";
import {
  entraInvokerConfigFromEnv,
  entraIssuer,
  verifyEntraToken,
} from "../entra-token.ts";
import { authorize, fetchPing } from "./google-id-token-fixtures.ts";

const { logError } = vi.hoisted(() => ({ logError: vi.fn() }));

vi.mock("../../logger.ts", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
}));

// Capture what the error handler logs for each refused request.
vi.mock("pino", () => ({
  pino: () => ({ error: logError, info: vi.fn(), warn: vi.fn() }),
}));

const TENANT_ID = "11111111-1111-1111-1111-111111111111";
const CLIENT_ID = "22222222-2222-2222-2222-222222222222";
const OTHER_ID = "33333333-3333-3333-3333-333333333333";
const KID = "test-key";

const signingKey = generateKeyPairSync("rsa", { modulusLength: 2048 });
const otherKey = generateKeyPairSync("rsa", { modulusLength: 2048 });

const jwks = {
  keys: [
    { ...signingKey.publicKey.export({ format: "jwk" }), kid: KID, use: "sig" },
  ],
};

const nowSeconds = () => Math.floor(Date.now() / 1000);

const signToken = (
  claims: Record<string, unknown> = {},
  key = signingKey.privateKey
) =>
  jwt.sign(
    {
      iss: entraIssuer(TENANT_ID),
      aud: CLIENT_ID,
      azp: CLIENT_ID,
      tid: TENANT_ID,
      iat: nowSeconds() - 60,
      nbf: nowSeconds() - 60,
      exp: nowSeconds() + 3600,
      ...claims,
    },
    key,
    { algorithm: "RS256", keyid: KID }
  );

describe("verifyEntraToken", () => {
  const fetchJwks = vi.fn();

  beforeEach(() => {
    fetchJwks.mockImplementation(async () => Response.json(jwks));
    vi.stubGlobal("fetch", fetchJwks);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    fetchJwks.mockReset();
  });

  // Folds a thrown verification error into a rejection, as the bearer middleware does.
  const accepts = (token: string) =>
    verifyEntraToken({ tenantId: TENANT_ID, clientId: CLIENT_ID })(token).catch(
      () => false
    );

  it("accepts a valid token", async () => {
    await expect(accepts(signToken())).resolves.toBe(true);
  });

  it("fetches the signing keys from the tenant's JWKS", async () => {
    await accepts(signToken());
    expect(fetchJwks).toHaveBeenCalledWith(
      `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`
    );
  });

  it("fetches the JWKS once for several tokens", async () => {
    const verify = verifyEntraToken({
      tenantId: TENANT_ID,
      clientId: CLIENT_ID,
    });
    await verify(signToken());
    await verify(signToken());
    expect(fetchJwks).toHaveBeenCalledTimes(1);
  });

  it("rejects a token from another tenant", async () => {
    await expect(
      accepts(signToken({ iss: entraIssuer(OTHER_ID) }))
    ).resolves.toBe(false);
  });

  it("rejects a token for another audience", async () => {
    await expect(accepts(signToken({ aud: OTHER_ID }))).resolves.toBe(false);
  });

  it("rejects a token from another caller", async () => {
    await expect(accepts(signToken({ azp: OTHER_ID }))).resolves.toBe(false);
  });

  it("rejects a token with no caller", async () => {
    await expect(accepts(signToken({ azp: undefined }))).resolves.toBe(false);
  });

  it("rejects an expired token", async () => {
    await expect(accepts(signToken({ exp: nowSeconds() - 60 }))).resolves.toBe(
      false
    );
  });

  it("rejects a token that isn't valid yet", async () => {
    await expect(accepts(signToken({ nbf: nowSeconds() + 600 }))).resolves.toBe(
      false
    );
  });

  it("rejects a token signed by another key", async () => {
    await expect(accepts(signToken({}, otherKey.privateKey))).resolves.toBe(
      false
    );
  });

  it("rejects a token whose payload was changed after signing", async () => {
    const [header, , signature] = signToken().split(".");
    const payload = Buffer.from(
      JSON.stringify({
        iss: entraIssuer(TENANT_ID),
        aud: CLIENT_ID,
        azp: CLIENT_ID,
        exp: nowSeconds() + 3600,
      })
    ).toString("base64url");
    await expect(accepts(`${header}.${payload}.${signature}`)).resolves.toBe(
      false
    );
  });

  it("rejects an unsigned token", async () => {
    const token = jwt.sign(
      {
        iss: entraIssuer(TENANT_ID),
        aud: CLIENT_ID,
        azp: CLIENT_ID,
        exp: nowSeconds() + 3600,
      },
      "",
      { algorithm: "none", keyid: KID }
    );
    await expect(accepts(token)).resolves.toBe(false);
  });

  it("rejects a token whose key isn't in the JWKS", async () => {
    const token = jwt.sign(
      { iss: entraIssuer(TENANT_ID), aud: CLIENT_ID, azp: CLIENT_ID },
      signingKey.privateKey,
      { algorithm: "RS256", keyid: "unknown-key", expiresIn: 3600 }
    );
    await expect(accepts(token)).resolves.toBe(false);
  });

  it("rejects a token that isn't a JWT", async () => {
    await expect(accepts("not-a-jwt")).resolves.toBe(false);
  });
});

describe("the log for an Entra token verifyEntraToken refuses", () => {
  const realFetch = globalThis.fetch;
  const jwksResponse = vi.fn<() => Promise<Response>>();

  beforeEach(() => {
    jwksResponse.mockImplementation(async () => Response.json(jwks));
    // Serve the JWKS from the stub and send the test's own requests through.
    vi.stubGlobal("fetch", (url: string, init?: RequestInit) =>
      url.startsWith("https://login.microsoftonline.com/")
        ? jwksResponse()
        : realFetch(url, init)
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    jwksResponse.mockReset();
    logError.mockClear();
  });

  const loggedErrors = () => JSON.stringify(logError.mock.calls);

  /** Sends `token` to the bearer check; returns the refusal and the response. */
  const refuse = async (token: string) => {
    const middlewares = [
      bearerAuthzMiddleware(
        verifyEntraToken({ tenantId: TENANT_ID, clientId: CLIENT_ID })
      ),
    ];
    const error = await authorize(middlewares[0]!, token);
    const response = await fetchPing({}, middlewares, {
      Authorization: `Bearer ${token}`,
    });
    expect(error).toBeInstanceOf(AuthError);
    expect(response).toEqual({
      status: 403,
      body: {
        error: {
          message: "Unauthorized",
          publicMessage: "P0 could not properly identify you.",
        },
      },
    });
    const { cause, stack } = error as AuthError;
    for (const kept of [
      JSON.stringify(error),
      stack,
      String((cause as Error).stack),
      loggedErrors(),
      JSON.stringify(response),
    ]) {
      expect(kept).not.toContain(token);
    }
    return cause as Error;
  };

  const encode = (part: string) => Buffer.from(part).toString("base64url");

  it.each([
    ["a token that isn't a JWT", () => "not-a-jwt", "not a JWT"],
    [
      "a JWT header over a payload that isn't JSON",
      () =>
        `${encode(JSON.stringify({ alg: "RS256", typ: "JWT", kid: KID }))}.${encode("payload")}.${encode("signature")}`,
      "not a JWT",
    ],
    [
      "no kid",
      () =>
        jwt.sign(
          { iss: entraIssuer(TENANT_ID), aud: CLIENT_ID, azp: CLIENT_ID },
          signingKey.privateKey,
          { algorithm: "RS256", expiresIn: 3600 }
        ),
      "no kid",
    ],
    [
      "a kid that isn't in the JWKS",
      () =>
        jwt.sign(
          { iss: entraIssuer(TENANT_ID), aud: CLIENT_ID, azp: CLIENT_ID },
          signingKey.privateKey,
          { algorithm: "RS256", keyid: "unknown-key", expiresIn: 3600 }
        ),
      "unknown kid",
    ],
    [
      "no signature",
      () =>
        jwt.sign(
          { iss: entraIssuer(TENANT_ID), aud: CLIENT_ID, azp: CLIENT_ID },
          "",
          { algorithm: "none", keyid: KID, expiresIn: 3600 }
        ),
      "no signature",
    ],
    [
      "alg HS256",
      () =>
        jwt.sign(
          { iss: entraIssuer(TENANT_ID), aud: CLIENT_ID, azp: CLIENT_ID },
          "secret",
          { algorithm: "HS256", keyid: KID, expiresIn: 3600 }
        ),
      "wrong algorithm",
    ],
    [
      "a signature by another key",
      () => signToken({}, otherKey.privateKey),
      "invalid signature",
    ],
    [
      "an nbf in the future",
      () => signToken({ nbf: nowSeconds() + 600 }),
      "not yet valid",
    ],
    [
      "an expired token",
      () => signToken({ exp: nowSeconds() - 60 }),
      "expired",
    ],
    ["another audience", () => signToken({ aud: OTHER_ID }), "wrong aud"],
    [
      "another tenant",
      () => signToken({ iss: entraIssuer(OTHER_ID) }),
      "wrong iss",
    ],
    ["another caller", () => signToken({ azp: OTHER_ID }), "wrong azp"],
    ["no caller", () => signToken({ azp: undefined }), "wrong azp"],
  ])("names the check for %s", async (_name, mint, check) => {
    const cause = await refuse(mint());

    expect(cause).toBeInstanceOf(TokenRefusal);
    expect(cause.message).toBe(`Entra token refused: ${check}`);
    expect(loggedErrors()).toContain(`Entra token refused: ${check}`);
  });

  it("names a failed JWKS fetch", async () => {
    jwksResponse.mockImplementation(
      async () => new Response(null, { status: 503 })
    );

    const cause = await refuse(signToken());

    expect(cause.message).toBe("Entra token refused: key set fetch failed");
    expect(loggedErrors()).not.toContain("discovery");
  });

  it("logs only that verification failed for an error it doesn't recognise", async () => {
    // A key set that doesn't parse fails with a message no check names.
    jwksResponse.mockImplementation(async () =>
      Response.json({ keys: "none" })
    );

    const cause = await refuse(signToken());

    expect(cause).not.toBeInstanceOf(TokenRefusal);
    expect(String(cause)).toBe("Error: Token verification failed");
    expect(loggedErrors()).toContain("Token verification failed");
  });
});

describe("entraInvokerConfigFromEnv", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("reads the tenant and client IDs", () => {
    vi.stubEnv("P0_INVOKER_TENANT_ID", TENANT_ID);
    vi.stubEnv("P0_INVOKER_CLIENT_ID", CLIENT_ID);
    expect(entraInvokerConfigFromEnv()).toEqual({
      tenantId: TENANT_ID,
      clientId: CLIENT_ID,
    });
  });

  it("ignores AZURE_CLIENT_ID, which is the Connector's outbound identity", () => {
    vi.stubEnv("P0_INVOKER_TENANT_ID", TENANT_ID);
    vi.stubEnv("P0_INVOKER_CLIENT_ID", "");
    vi.stubEnv("AZURE_CLIENT_ID", CLIENT_ID);
    expect(() => entraInvokerConfigFromEnv()).toThrow("P0_INVOKER_CLIENT_ID");
  });
});
