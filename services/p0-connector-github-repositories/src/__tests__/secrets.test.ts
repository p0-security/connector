import { ConnectorError } from "@p0security/connector-core";
import {
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
} from "@p0security/secret-manager-client";
import type * as secretManagerClient from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PrivateKeyPointer } from "../accesses/role/definition.ts";
import { getGithubPrivateKey } from "../secrets.ts";

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factory runs.
const vault = vi.hoisted(() => ({
  createSecretManagerClient: vi.fn(),
  getSecretValue: vi.fn(),
}));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => ({
  ...(await importOriginal<typeof secretManagerClient>()),
  createSecretManagerClient: vault.createSecretManagerClient,
}));

const AWS: PrivateKeyPointer = {
  manager: "aws",
  secretId: "gh-app-key",
  region: "us-west-2",
};

const PEM =
  "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";

const connectorError = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    if (error instanceof ConnectorError) return error.data;
    throw error;
  }
  throw new Error("expected the call to throw");
};

beforeEach(() => {
  vi.clearAllMocks();
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  });
  vault.getSecretValue.mockResolvedValue({ value: PEM });
});

describe("getGithubPrivateKey", () => {
  it("reads the secret from the region the pointer names", async () => {
    await expect(getGithubPrivateKey(AWS)).resolves.toBe(PEM);
    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "aws",
      region: "us-west-2",
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({ ref: "gh-app-key" });
  });

  it("turns escaped newlines back into real ones", async () => {
    vault.getSecretValue.mockResolvedValue({
      value: PEM.replace(/\n/g, "\\n"),
    });
    await expect(getGithubPrivateKey(AWS)).resolves.toBe(PEM);
  });

  it("decodes a binary secret as UTF-8", async () => {
    vault.getSecretValue.mockResolvedValue({ value: Buffer.from(PEM, "utf8") });
    await expect(getGithubPrivateKey(AWS)).resolves.toBe(PEM);
  });

  it("reports a missing secret as object_not_found", async () => {
    vault.getSecretValue.mockRejectedValue(
      new SecretNotFoundError("gh-app-key" as SecretRef)
    );

    const data = await connectorError(() => getGithubPrivateKey(AWS));

    expect(data.type).toBe("object_not_found");
    expect(data.payload).toEqual({ query: "gh-app-key", manager: "aws" });
    expect(data.message).toBe(
      "The connector couldn't find the GitHub App private key secret gh-app-key. Check the private key secret in the P0 install, and that the secret still exists."
    );
  });

  it("reports a denied read as insufficient_privileges, naming what to grant", async () => {
    vault.getSecretValue.mockRejectedValue(new UnauthorizedError("aws"));

    const data = await connectorError(() => getGithubPrivateKey(AWS));

    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toEqual({ secretId: "gh-app-key", manager: "aws" });
    expect(data.message).toBe(
      "The connector isn't allowed to read the GitHub App private key secret gh-app-key. Grant the connector's identity secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key."
    );
  });

  it("lets anything else through as is", async () => {
    const error = new Error("vault exploded");
    vault.getSecretValue.mockRejectedValue(error);
    await expect(getGithubPrivateKey(AWS)).rejects.toBe(error);
  });
});
