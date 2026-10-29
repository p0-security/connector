import { ConnectorError } from "@p0security/connector-core";
import {
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
} from "@p0security/connector-secret-manager-client";
import type * as secretManagerClient from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PrivateKeyPointer } from "../accesses/common/definition.ts";
import { fetchGitHubPrivateKey } from "../secrets.ts";

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factory runs.
const vault = vi.hoisted(() => ({
  createSecretManagerClient: vi.fn(),
  getSecretValue: vi.fn(),
}));

vi.mock(
  "@p0security/connector-secret-manager-client",
  async (importOriginal) => ({
    ...(await importOriginal<typeof secretManagerClient>()),
    createSecretManagerClient: vault.createSecretManagerClient,
  })
);

const AWS: PrivateKeyPointer = {
  manager: "aws",
  secretId: "gh-app-key",
  region: "us-west-2",
};
const GCP: PrivateKeyPointer = {
  manager: "gcp",
  secretId: "projects/acme-prod/secrets/gh-app-key",
  projectId: "acme-prod",
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

describe("fetchGitHubPrivateKey", () => {
  it.each([
    [AWS, { provider: "aws", region: "us-west-2" }],
    [GCP, { provider: "gcp", projectId: "acme-prod" }],
  ])(
    "reads the secret from the vault the pointer names (%o)",
    async (pointer, config) => {
      await expect(fetchGitHubPrivateKey(pointer)).resolves.toBe(PEM);
      expect(vault.createSecretManagerClient).toHaveBeenCalledWith(config);
      expect(vault.getSecretValue).toHaveBeenCalledWith({
        ref: pointer.secretId,
      });
    }
  );

  it("turns escaped newlines back into real ones", async () => {
    vault.getSecretValue.mockResolvedValue({
      value: PEM.replace(/\n/g, "\\n"),
    });
    await expect(fetchGitHubPrivateKey(AWS)).resolves.toBe(PEM);
  });

  // Google Secret Manager always returns a secret's value as bytes.
  it("decodes a binary secret as UTF-8", async () => {
    vault.getSecretValue.mockResolvedValue({ value: Buffer.from(PEM, "utf8") });
    await expect(fetchGitHubPrivateKey(GCP)).resolves.toBe(PEM);
  });

  // P0 tells the key's errors from the connector's others by the vault's
  // `manager` in the payload.
  it.each([AWS, GCP])(
    "reports a missing secret as object_not_found (%o)",
    async (pointer) => {
      vault.getSecretValue.mockRejectedValue(
        new SecretNotFoundError(pointer.secretId as SecretRef)
      );

      const data = await connectorError(() => fetchGitHubPrivateKey(pointer));

      expect(data.type).toBe("object_not_found");
      expect(data.payload).toEqual({
        query: pointer.secretId,
        manager: pointer.manager,
      });
      expect(data.message).toBe(
        `The connector couldn't find the GitHub App private key secret ${pointer.secretId}. Check the private key secret in the P0 install, and that the secret still exists.`
      );
    }
  );

  it.each([
    [
      AWS,
      "The connector isn't allowed to read the GitHub App private key secret gh-app-key. Grant the connector's identity secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key.",
    ],
    [
      GCP,
      "The connector isn't allowed to read the GitHub App private key secret projects/acme-prod/secrets/gh-app-key. Grant the connector's identity secretmanager.versions.access and secretmanager.versions.get on that secret.",
    ],
  ])(
    "reports a denied read as insufficient_privileges, naming what to grant (%o)",
    async (pointer, message) => {
      vault.getSecretValue.mockRejectedValue(
        new UnauthorizedError(pointer.manager)
      );

      const data = await connectorError(() => fetchGitHubPrivateKey(pointer));

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({
        secretId: pointer.secretId,
        manager: pointer.manager,
      });
      expect(data.message).toBe(message);
    }
  );

  it("lets anything else through as is", async () => {
    const error = new Error("vault exploded");
    vault.getSecretValue.mockRejectedValue(error);
    await expect(fetchGitHubPrivateKey(AWS)).rejects.toBe(error);
  });
});
