import {
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
} from "@p0security/connector-secret-manager-client";
import type * as secretManagerClient from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getOrgAccessToken } from "../secrets.ts";
import { AWS_SECRET, GCP_SECRET, TOKEN } from "./fixtures.ts";
import { connectorError } from "./helpers.ts";

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

const VERSION = "docker-oat/versions/3";

const holding = (value: Buffer | string) => ({
  value,
  version: { ref: VERSION },
});

beforeEach(() => {
  vi.clearAllMocks();
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  });
  vault.getSecretValue.mockResolvedValue(holding(TOKEN));
});

describe("getOrgAccessToken", () => {
  it("reads an AWS pointer's secret from the region it names", async () => {
    await getOrgAccessToken(AWS_SECRET);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "aws",
      region: "us-west-2",
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({ ref: "docker-oat" });
  });

  it("reads a Google pointer's secret from the project it names", async () => {
    await getOrgAccessToken(GCP_SECRET);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "gcp",
      projectId: "acme-prod",
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({ ref: "docker-oat" });
  });

  // The version is what tells the connector the secret was rotated.
  it("returns the token with the version it was read from", async () => {
    await expect(getOrgAccessToken(AWS_SECRET)).resolves.toEqual({
      token: TOKEN,
      version: VERSION,
    });
  });

  // Google Secret Manager always returns bytes.
  it("decodes a binary secret as UTF-8", async () => {
    vault.getSecretValue.mockResolvedValue(holding(Buffer.from(TOKEN, "utf8")));

    await expect(getOrgAccessToken(GCP_SECRET)).resolves.toMatchObject({
      token: TOKEN,
    });
  });

  // `echo "$TOKEN" | gcloud secrets versions add ...` stores a newline too.
  it("drops whitespace around the token", async () => {
    vault.getSecretValue.mockResolvedValue(holding(`  ${TOKEN}\n`));

    await expect(getOrgAccessToken(AWS_SECRET)).resolves.toMatchObject({
      token: TOKEN,
    });
  });

  // The requestor can't fix the install, so it isn't a validation_error.
  it.each([
    ["empty", ""],
    ["blank", " \n"],
  ])(
    "reports an %s secret as insufficient_privileges",
    async (_case, value) => {
      vault.getSecretValue.mockResolvedValue(holding(value));

      const data = await connectorError(() => getOrgAccessToken(AWS_SECRET));

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({ secretId: "docker-oat", manager: "aws" });
      expect(data.message).toBe(
        "The Docker Hub organization access token secret docker-oat is empty. Store the organization access token in it."
      );
    }
  );

  it.each([AWS_SECRET, GCP_SECRET])(
    "reports a missing secret in $manager as object_not_found",
    async (tokenSecret) => {
      vault.getSecretValue.mockRejectedValue(
        new SecretNotFoundError("docker-oat" as SecretRef)
      );

      const data = await connectorError(() => getOrgAccessToken(tokenSecret));

      expect(data.type).toBe("object_not_found");
      expect(data.payload).toEqual({
        query: "docker-oat",
        manager: tokenSecret.manager,
      });
      expect(data.message).toBe(
        "The connector couldn't find the Docker Hub organization access token secret docker-oat. Check the token secret in the P0 install, and that the secret still exists."
      );
    }
  );

  it.each([
    {
      tokenSecret: AWS_SECRET,
      grant:
        "secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key",
    },
    // The shared client reads the version's metadata after its payload.
    {
      tokenSecret: GCP_SECRET,
      grant:
        "secretmanager.versions.access and secretmanager.versions.get on that secret",
    },
  ])(
    "reports a denied read in $tokenSecret.manager as insufficient_privileges, naming what to grant",
    async ({ tokenSecret, grant }) => {
      vault.getSecretValue.mockRejectedValue(
        new UnauthorizedError(tokenSecret.manager)
      );

      const data = await connectorError(() => getOrgAccessToken(tokenSecret));

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({
        secretId: "docker-oat",
        manager: tokenSecret.manager,
      });
      expect(data.message).toBe(
        `The connector isn't allowed to read the Docker Hub organization access token secret docker-oat. Grant the connector's identity ${grant}.`
      );
    }
  );

  it("lets anything else through as is", async () => {
    const error = new Error("vault exploded");
    vault.getSecretValue.mockRejectedValue(error);

    await expect(getOrgAccessToken(AWS_SECRET)).rejects.toBe(error);
  });
});
