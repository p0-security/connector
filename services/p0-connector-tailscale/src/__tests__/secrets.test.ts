import {
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
} from "@p0security/secret-manager-client";
import type * as secretManagerClient from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getClientSecret } from "../secrets.ts";
import { AWS_SECRET, CLIENT_SECRET, GCP_SECRET } from "./fixtures.ts";
import { connectorError } from "./helpers.ts";

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factory runs.
const vault = vi.hoisted(() => ({
  createSecretManagerClient: vi.fn(),
  getSecretValue: vi.fn(),
}));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => ({
  ...(await importOriginal<typeof secretManagerClient>()),
  createSecretManagerClient: vault.createSecretManagerClient,
}));

const VERSION = "tailscale-oauth-client/versions/3";

const holding = (value: Buffer | string) => ({
  value,
  version: { ref: VERSION },
});

beforeEach(() => {
  vi.clearAllMocks();
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  });
  vault.getSecretValue.mockResolvedValue(holding(CLIENT_SECRET));
});

describe("getClientSecret", () => {
  it("reads an AWS pointer's secret from the region it names", async () => {
    await getClientSecret(AWS_SECRET);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "aws",
      region: "us-west-2",
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({
      ref: "tailscale-oauth-client",
    });
  });

  it("reads a Google pointer's secret from the project it names", async () => {
    await getClientSecret(GCP_SECRET);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "gcp",
      projectId: "acme-prod",
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({
      ref: "tailscale-oauth-client",
    });
  });

  // The version is what tells the connector the secret was rotated.
  it("returns the secret with the version it was read from", async () => {
    await expect(getClientSecret(AWS_SECRET)).resolves.toEqual({
      secret: CLIENT_SECRET,
      version: VERSION,
    });
  });

  // Google Secret Manager always returns bytes.
  it("decodes a binary secret as UTF-8", async () => {
    vault.getSecretValue.mockResolvedValue(
      holding(Buffer.from(CLIENT_SECRET, "utf8"))
    );

    await expect(getClientSecret(GCP_SECRET)).resolves.toMatchObject({
      secret: CLIENT_SECRET,
    });
  });

  // `echo "$CLIENT_SECRET" | gcloud secrets versions add ...` stores a newline too.
  it("drops whitespace around the secret", async () => {
    vault.getSecretValue.mockResolvedValue(holding(`  ${CLIENT_SECRET}\n`));

    await expect(getClientSecret(AWS_SECRET)).resolves.toMatchObject({
      secret: CLIENT_SECRET,
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

      const data = await connectorError(() => getClientSecret(AWS_SECRET));

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({
        secretId: "tailscale-oauth-client",
        manager: "aws",
      });
      expect(data.message).toBe(
        "The Tailscale OAuth client secret tailscale-oauth-client is empty. Store the Tailscale OAuth client's secret in it."
      );
    }
  );

  it.each([AWS_SECRET, GCP_SECRET])(
    "reports a missing secret in $manager as object_not_found",
    async (pointer) => {
      vault.getSecretValue.mockRejectedValue(
        new SecretNotFoundError("tailscale-oauth-client" as SecretRef)
      );

      const data = await connectorError(() => getClientSecret(pointer));

      expect(data.type).toBe("object_not_found");
      expect(data.payload).toEqual({
        query: "tailscale-oauth-client",
        manager: pointer.manager,
      });
      expect(data.message).toBe(
        "The connector couldn't find the Tailscale OAuth client secret tailscale-oauth-client. Check the client secret in the P0 install, and that the secret still exists."
      );
    }
  );

  it.each([
    {
      pointer: AWS_SECRET,
      grant:
        "secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key",
    },
    // The shared client reads the version's metadata after its payload.
    {
      pointer: GCP_SECRET,
      grant:
        "secretmanager.versions.access and secretmanager.versions.get on that secret",
    },
  ])(
    "reports a denied read in $pointer.manager as insufficient_privileges, naming what to grant",
    async ({ pointer, grant }) => {
      vault.getSecretValue.mockRejectedValue(
        new UnauthorizedError(pointer.manager)
      );

      const data = await connectorError(() => getClientSecret(pointer));

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({
        secretId: "tailscale-oauth-client",
        manager: pointer.manager,
      });
      expect(data.message).toBe(
        `The connector isn't allowed to read the Tailscale OAuth client secret tailscale-oauth-client. Grant the connector's identity ${grant}.`
      );
    }
  );

  it("lets anything else through as is", async () => {
    const error = new Error("vault exploded");
    vault.getSecretValue.mockRejectedValue(error);

    await expect(getClientSecret(AWS_SECRET)).rejects.toBe(error);
  });
});
