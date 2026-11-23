import jwt from "jsonwebtoken";
import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import { TokenRefusal } from "../../http/middlewares/bearer.ts";
import {
  identityKeysFromJwks,
  newP0IdentityTokenVerifier,
} from "../p0-identity-token.ts";
import {
  IDENTITY_AUDIENCE,
  IDENTITY_JWKS,
  jwk,
  keyA,
  keyB,
  newKey,
  nowSeconds,
  signIdentityToken,
} from "./p0-identity-token-fixtures.ts";

// Keep the admitted-token log line out of the test output.
vi.mock("../../logger.ts", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
}));

describe("identityKeysFromJwks", () => {
  it("returns each key by kid", () => {
    expect([...identityKeysFromJwks(IDENTITY_JWKS).keys()]).toEqual([
      "key-a",
      "key-b",
    ]);
  });

  it.each([
    ["unset", undefined, /is not set/],
    ["empty", "", /is not set/],
    ["not JSON", "{keys:", /is not JSON/],
    ["without keys", JSON.stringify({ keys: [] }), /one or two RSA keys/],
    [
      "with three keys",
      JSON.stringify({
        keys: [jwk(keyA, "a"), jwk(keyB, "b"), jwk(newKey(), "c")],
      }),
      /one or two RSA keys/,
    ],
    [
      "with a duplicate kid",
      JSON.stringify({ keys: [jwk(keyA, "same"), jwk(keyB, "same")] }),
      /has the kid same twice/,
    ],
    [
      "with an EC key",
      JSON.stringify({
        keys: [
          {
            ...generateKeyPairSync("ec", {
              namedCurve: "P-256",
            }).publicKey.export({ format: "jwk" }),
            kid: "ec",
            alg: "RS256",
          },
        ],
      }),
      /one or two RSA keys/,
    ],
    [
      "with a 1024-bit key",
      JSON.stringify({ keys: [jwk(newKey(1024), "short")] }),
      /key short is shorter than 2048 bits/,
    ],
    [
      "with alg RS512",
      JSON.stringify({ keys: [{ ...jwk(keyA, "a"), alg: "RS512" }] }),
      /one or two RSA keys/,
    ],
    [
      "without alg",
      JSON.stringify({ keys: [{ ...jwk(keyA, "a"), alg: undefined }] }),
      /one or two RSA keys/,
    ],
  ])("throws when the key set is %s", (_name, value, message) => {
    expect(() => identityKeysFromJwks(value)).toThrow(message);
  });
});

describe("newP0IdentityTokenVerifier", () => {
  const verify = newP0IdentityTokenVerifier({
    audience: IDENTITY_AUDIENCE,
    keys: identityKeysFromJwks(IDENTITY_JWKS),
  });

  it("admits a valid token", async () => {
    await expect(verify(signIdentityToken())).resolves.toBe(true);
  });

  it("admits a token signed with either key", async () => {
    const token = signIdentityToken({}, { key: keyB.privateKey, kid: "key-b" });

    await expect(verify(token)).resolves.toBe(true);
  });

  it("admits a token issued up to 60 seconds ahead", async () => {
    const iat = nowSeconds() + 50;

    await expect(
      verify(signIdentityToken({ iat, exp: iat + 15 * 60 }))
    ).resolves.toBe(true);
  });

  it("admits a token expired less than 60 seconds ago", async () => {
    const exp = nowSeconds() - 30;

    await expect(
      verify(signIdentityToken({ iat: exp - 15 * 60, exp }))
    ).resolves.toBe(true);
  });

  const refusals: [string, () => string, RegExp][] = [
    ["not a JWT", () => "not-a-jwt", /not a JWT/],
    [
      "an unknown kid",
      () => signIdentityToken({}, { kid: "key-c" }),
      /unknown kid/,
    ],
    [
      "no kid",
      () =>
        jwt.sign(
          { iss: "p0", aud: IDENTITY_AUDIENCE, sub: "tenant-a" },
          keyA.privateKey,
          { algorithm: "RS256" }
        ),
      /unknown kid/,
    ],
    [
      "a bad signature",
      () => signIdentityToken({}, { key: newKey().privateKey }),
      /invalid signature/,
    ],
    [
      "a signature by the other key",
      () => signIdentityToken({}, { key: keyB.privateKey, kid: "key-a" }),
      /invalid signature/,
    ],
    [
      "alg HS256",
      () =>
        jwt.sign({ iss: "p0", aud: IDENTITY_AUDIENCE, sub: "t" }, "secret", {
          algorithm: "HS256",
          keyid: "key-a",
        }),
      /invalid algorithm/,
    ],
    [
      "alg none",
      () => {
        const encode = (part: object) =>
          Buffer.from(JSON.stringify(part)).toString("base64url");
        const now = nowSeconds();
        return `${encode({ alg: "none", typ: "JWT", kid: "key-a" })}.${encode({
          iss: "p0",
          aud: IDENTITY_AUDIENCE,
          sub: "tenant-a",
          iat: now,
          exp: now + 15 * 60,
        })}.`;
      },
      /signature is required/,
    ],
    [
      "an nbf in the future",
      () => signIdentityToken({ nbf: nowSeconds() + 5 * 60 }),
      /jwt not active/,
    ],
    ["the wrong iss", () => signIdentityToken({ iss: "other" }), /issuer/],
    [
      "the wrong aud",
      () =>
        signIdentityToken({
          aud: "https://connector.example.com/p0?p0_org=tenant-b",
        }),
      /wrong aud/,
    ],
    [
      "aud as a list",
      () => signIdentityToken({ aud: [IDENTITY_AUDIENCE] }),
      /wrong aud/,
    ],
    ["no sub", () => signIdentityToken({ sub: undefined }), /no sub/],
    [
      "expired over 60 seconds ago",
      () => {
        const exp = nowSeconds() - 90;
        return signIdentityToken({ iat: exp - 15 * 60, exp });
      },
      /jwt expired/,
    ],
    ["no exp", () => signIdentityToken({ exp: undefined }), /no iat or exp/],
    ["no iat", () => signIdentityToken({ iat: undefined }), /no iat or exp/],
    [
      "an iat over 60 seconds ahead",
      () => {
        const iat = nowSeconds() + 120;
        return signIdentityToken({ iat, exp: iat + 15 * 60 });
      },
      /iat is in the future/,
    ],
    [
      "a lifetime over 15 minutes",
      () => signIdentityToken({ exp: nowSeconds() + 15 * 60 + 1 }),
      /lives longer than 15 minutes/,
    ],
  ];

  it.each(refusals)("refuses a token with %s", async (_name, token, check) => {
    const signed = token();

    const error = await verify(signed).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(TokenRefusal);
    expect((error as Error).message).toMatch(check);
    // The failure names the check, never the token.
    expect((error as Error).message).not.toContain(signed);
  });
});
