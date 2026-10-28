import { ConnectorError } from "@p0security/connector";
import jwt from "jsonwebtoken";
import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createAppJwt } from "../jwt.ts";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

const NOW = new Date("2026-10-01T00:00:00Z");
const NOW_SECONDS = NOW.getTime() / 1000;

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
});

const thrown = (run: () => unknown): unknown => {
  try {
    run();
  } catch (error) {
    return error;
  }
  throw new Error("expected the call to throw");
};

describe("createAppJwt", () => {
  it("signs an RS256 JWT issued by the app, backdated 60s and valid for 9 minutes", () => {
    const token = createAppJwt({ appId: "123456", privateKey });

    const claims = jwt.verify(token, publicKey, {
      algorithms: ["RS256"],
    }) as jwt.JwtPayload;
    expect(claims.iss).toBe("123456");
    expect(claims.iat).toBe(NOW_SECONDS - 60);
    expect(claims.exp).toBe(NOW_SECONDS - 60 + 9 * 60);
    // GitHub rejects a JWT that expires more than 10 minutes out.
    expect(claims.exp! - NOW_SECONDS).toBeLessThan(10 * 60);
  });

  it("refuses a key that isn't a PEM private key, and never repeats it", () => {
    const SENTINEL = "SENTINEL-not-a-pem-7f3a9c";

    const error = thrown(() =>
      createAppJwt({ appId: "123456", privateKey: SENTINEL })
    );

    expect(error).toBeInstanceOf(ConnectorError);
    const { data } = error as ConnectorError;
    expect(data.type).toBe("validation_error");
    expect(data.payload).toEqual({ appId: "123456" });
    expect(data.message).not.toContain(SENTINEL);
    expect(JSON.stringify(data)).not.toContain(SENTINEL);
    expect(JSON.stringify(error)).not.toContain(SENTINEL);
    expect(String((error as Error).stack)).not.toContain(SENTINEL);
  });
});
