/**
 * Throwaway identity keys and a signer shaped like P0's, shared by the tests
 * for the identity token verifier and the trusted-proxy mode. The keys are
 * generated when the tests run.
 */
import jwt from "jsonwebtoken";
import { generateKeyPairSync } from "node:crypto";

export const IDENTITY_AUDIENCE =
  "https://connector.example.com/p0?p0_org=tenant-a";

export const newKey = (modulusLength = 2048) =>
  generateKeyPairSync("rsa", { modulusLength });

export const keyA = newKey();
export const keyB = newKey();

/** One key of a JWKS as the provisioning command prints it. */
export const jwk = (key: ReturnType<typeof newKey>, kid: string) => ({
  ...key.publicKey.export({ format: "jwk" }),
  kid,
  alg: "RS256",
  use: "sig",
});

export const IDENTITY_JWKS = JSON.stringify({
  keys: [jwk(keyA, "key-a"), jwk(keyB, "key-b")],
});

export const nowSeconds = () => Math.floor(Date.now() / 1000);

/**
 * Signs an identity token as P0 does, with any claim or header overridden. A
 * claim set to `undefined` is left out, `iat` included.
 */
export const signIdentityToken = (
  claims: Record<string, unknown> = {},
  {
    key = keyA.privateKey,
    kid = "key-a",
  }: { key?: ReturnType<typeof newKey>["privateKey"]; kid?: string } = {}
) => {
  const payload = Object.fromEntries(
    Object.entries({
      iss: "p0",
      aud: IDENTITY_AUDIENCE,
      sub: "tenant-a",
      iat: nowSeconds(),
      exp: nowSeconds() + 15 * 60,
      ...claims,
    }).filter(([, value]) => value !== undefined)
  );
  // Without `noTimestamp`, jwt.sign adds an `iat` the payload leaves out.
  return jwt.sign(payload, key, {
    algorithm: "RS256",
    keyid: kid,
    noTimestamp: payload.iat === undefined,
  });
};
