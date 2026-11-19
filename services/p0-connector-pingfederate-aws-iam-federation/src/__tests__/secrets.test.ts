import {
  type SecretManagerClient,
  SecretNotFoundError,
  type SecretRef,
  type SecretValue,
  UnauthorizedError,
} from "@p0security/connector-secret-manager-client";
import type * as secretManagerClient from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { readScimPassword } from "../secrets.ts";
import {
  AWS_SECRET,
  SCIM_PASSWORD,
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

const read = () => readScimPassword(AWS_SECRET, logger);

beforeEach(() => {
  vi.clearAllMocks();
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  } as unknown as SecretManagerClient);
  vault.getSecretValue.mockResolvedValue(holding(SCIM_PASSWORD));
});

describe("readScimPassword", () => {
  it("reads the password, with its spaces, from the secret the pointer names", async () => {
    await expect(read()).resolves.toBe(SCIM_PASSWORD);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "aws",
      region: AWS_SECRET.region,
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({
      ref: AWS_SECRET.secretId,
    });
  });

  it("reads a password given as bytes, without a line break at its end", async () => {
    vault.getSecretValue.mockResolvedValue(
      holding(Buffer.from(`${SCIM_PASSWORD}\n`))
    );

    await expect(read()).resolves.toBe(SCIM_PASSWORD);
  });

  it("refuses an empty secret", async () => {
    vault.getSecretValue.mockResolvedValue(holding(""));

    const error = await connectorError(read);

    expect(error.data).toMatchObject({ type: "validation_error" });
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
