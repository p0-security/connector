import {
  type SecretManagerClient,
  SecretNotFoundError,
  type SecretRef,
  type SecretValue,
  UnauthorizedError,
} from "@p0security/connector-secret-manager-client";
import type * as secretManagerClient from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { readClientSecret } from "../secrets.ts";
import {
  AWS_SECRET,
  CLIENT_SECRET,
  connectorError,
  logger,
} from "./fixtures.ts";

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

const read = () => readClientSecret(AWS_SECRET, logger);

beforeEach(() => {
  vi.clearAllMocks();
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  } as unknown as SecretManagerClient);
  vault.getSecretValue.mockResolvedValue(holding(CLIENT_SECRET));
});

describe("readClientSecret", () => {
  it("reads the client secret from the secret the pointer names", async () => {
    await expect(read()).resolves.toBe(CLIENT_SECRET);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "aws",
      region: AWS_SECRET.region,
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({
      ref: AWS_SECRET.secretId,
    });
  });

  it("reads a client secret given as bytes, without the whitespace around it", async () => {
    vault.getSecretValue.mockResolvedValue(
      holding(Buffer.from(` ${CLIENT_SECRET}\n`))
    );

    await expect(read()).resolves.toBe(CLIENT_SECRET);
  });

  it.each([
    ["empty", ""],
    ["a value with a line break in it", `${CLIENT_SECRET}\nX-Other: 1`],
  ])("refuses a secret that is %s, without quoting it", async (_, value) => {
    vault.getSecretValue.mockResolvedValue(holding(value));

    const error = await connectorError(read);

    expect(error.data).toMatchObject({ type: "validation_error" });
    expect(error.message).not.toContain(CLIENT_SECRET);
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
