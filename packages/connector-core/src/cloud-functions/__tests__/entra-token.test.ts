import jwt from "jsonwebtoken";
import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  entraInvokerConfigFromEnv,
  entraIssuer,
  verifyEntraToken,
} from "../entra-token.ts";

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
