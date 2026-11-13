import {
  type SecretManagerClient,
  SecretNotFoundError,
  type SecretRef,
  type SecretValue,
  UnauthorizedError,
} from "@p0security/connector-secret-manager-client";
import type * as secretManagerClient from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { readPrivateKey } from "../secrets.ts";
import { AWS_SECRET, JWK, KEYS, connectorError, logger } from "./fixtures.ts";

const vault = vi.hoisted(() => ({
  createSecretManagerClient:
    vi.fn<typeof secretManagerClient.createSecretManagerClient>(),
  getSecretValue:
    vi.fn<secretManagerClient.SecretManagerClient["getSecretValue"]>(),
}));

vi.mock(
  "@p0security/connector-secret-manager-client",
  async (importOriginal) => ({
    ...(await importOriginal<typeof secretManagerClient>()),
    createSecretManagerClient: vault.createSecretManagerClient,
  })
);

const holding = (value: Buffer | string) =>
  ({ value }) as unknown as SecretValue;

const read = () => readPrivateKey(AWS_SECRET, logger);

beforeEach(() => {
  vi.clearAllMocks();
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  } as unknown as SecretManagerClient);
  vault.getSecretValue.mockResolvedValue(holding(JSON.stringify(JWK)));
});

describe("readPrivateKey", () => {
  it("reads the JWK from the secret the pointer names", async () => {
    const { key, kid } = await read();

    expect(kid).toBe("key-1");
    expect(key.export({ format: "jwk" })).toEqual(
      KEYS.privateKey.export({ format: "jwk" })
    );
    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "aws",
      region: AWS_SECRET.region,
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({
      ref: AWS_SECRET.secretId,
    });
  });

  it("reads a JWK given as bytes", async () => {
    vault.getSecretValue.mockResolvedValue(
      holding(Buffer.from(JSON.stringify(JWK)))
    );

    await expect(read()).resolves.toMatchObject({ kid: "key-1" });
  });

  it.each([
    ["not JSON", "-----BEGIN PRIVATE KEY-----"],
    ["a public key", JSON.stringify(KEYS.publicKey.export({ format: "jwk" }))],
    ["a key that isn't RSA", JSON.stringify({ kty: "EC", d: "x" })],
    ["a broken RSA key", JSON.stringify({ kty: "RSA", d: "x" })],
  ])("refuses %s, without quoting it", async (_, value) => {
    vault.getSecretValue.mockResolvedValue(holding(value));

    const error = await connectorError(read);

    expect(error.data).toMatchObject({ type: "validation_error" });
    expect(error.message).not.toContain(value);
  });

  it.each([
    [
      new SecretNotFoundError(AWS_SECRET.secretId as SecretRef),
      "object_not_found",
    ],
    [new UnauthorizedError("aws"), "insufficient_privileges"],
  ])("maps %o to %s", async (thrown, type) => {
    vault.getSecretValue.mockRejectedValue(thrown);

    const error = await connectorError(read);

    expect(error.data.type).toBe(type);
    expect(error.message).not.toContain(AWS_SECRET.secretId);
  });
});
