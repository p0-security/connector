import {
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
} from "@p0security/connector-secret-manager-client";
import type * as secretManagerClient from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { readApiKey } from "../secrets.ts";
import {
  AWS_SECRET,
  GCP_SECRET,
  KEY_ID,
  KEY_SECRET,
  STORED_KEY,
} from "./fixtures.ts";
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

const VERSION = "clickhouse-api-key/versions/3";

const SHAPE =
  'Store {"keyId": "<the API key ID>", "keySecret": "<the API key secret>"} as its value.';

const holding = (value: Buffer | string) => ({
  value,
  version: { ref: VERSION },
});

beforeEach(() => {
  vi.clearAllMocks();
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  });
  vault.getSecretValue.mockResolvedValue(holding(STORED_KEY));
});

describe("readApiKey", () => {
  it("reads an AWS pointer's secret from the region it names", async () => {
    await readApiKey(AWS_SECRET);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "aws",
      region: "us-west-2",
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({
      ref: "clickhouse-api-key",
    });
  });

  it("reads a Google pointer's secret from the project it names", async () => {
    await readApiKey(GCP_SECRET);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "gcp",
      projectId: "acme-prod",
    });
  });

  it("returns the key with the version it was read from", async () => {
    await expect(readApiKey(AWS_SECRET)).resolves.toEqual({
      keyId: KEY_ID,
      keySecret: KEY_SECRET,
      version: VERSION,
    });
  });

  // Google Secret Manager always returns bytes.
  it("decodes a binary secret as UTF-8", async () => {
    vault.getSecretValue.mockResolvedValue(
      holding(Buffer.from(STORED_KEY, "utf8"))
    );

    await expect(readApiKey(GCP_SECRET)).resolves.toMatchObject({
      keySecret: KEY_SECRET,
    });
  });

  // `echo "$KEY" | gcloud secrets versions add ...` stores a newline too.
  it("drops whitespace around the JSON", async () => {
    vault.getSecretValue.mockResolvedValue(holding(`  ${STORED_KEY}\n`));

    await expect(readApiKey(AWS_SECRET)).resolves.toMatchObject({
      keyId: KEY_ID,
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

      await expect(
        connectorError(() => readApiKey(AWS_SECRET))
      ).resolves.toEqual({
        type: "insufficient_privileges",
        message: `The ClickHouse Cloud API key secret in AWS Secrets Manager is empty. ${SHAPE}`,
        payload: { manager: "aws" },
      });
    }
  );

  it.each([
    ["the bare key secret", KEY_SECRET, ": it isn't a JSON object"],
    [
      "a JSON array",
      JSON.stringify([KEY_ID, KEY_SECRET]),
      ": it isn't a JSON object",
    ],
    [
      "no key secret",
      JSON.stringify({ keyId: KEY_ID }),
      ": keySecret is missing or not valid",
    ],
    [
      "neither field",
      JSON.stringify({}),
      ": keyId, keySecret are missing or not valid",
    ],
    [
      "a key ID with a colon",
      JSON.stringify({ keyId: "a:b", keySecret: KEY_SECRET }),
      ": keyId is missing or not valid",
    ],
    [
      "a key secret with a line break",
      JSON.stringify({ keyId: KEY_ID, keySecret: `${KEY_SECRET}\n` }),
      ": keySecret is missing or not valid",
    ],
    [
      "a number for the key secret",
      JSON.stringify({ keyId: KEY_ID, keySecret: 42 }),
      ": keySecret is missing or not valid",
    ],
    [
      "the console's field names",
      JSON.stringify({ key_id: KEY_ID, key_secret: KEY_SECRET }),
      ": keyId, keySecret are missing or not valid, and it has fields besides keyId and keySecret",
    ],
    [
      "an extra field",
      JSON.stringify({
        keyId: KEY_ID,
        keySecret: KEY_SECRET,
        note: KEY_SECRET,
      }),
      ": it has fields besides keyId and keySecret",
    ],
  ])(
    "reports a secret holding %s as insufficient_privileges, quoting nothing in it",
    async (_case, value, problem) => {
      vault.getSecretValue.mockResolvedValue(holding(value));

      const data = await connectorError(() => readApiKey(GCP_SECRET));

      expect(data).toEqual({
        type: "insufficient_privileges",
        message: `The ClickHouse Cloud API key secret in Google Secret Manager isn't the JSON the connector expects${problem}. ${SHAPE}`,
        payload: { manager: "gcp" },
      });
      expect(JSON.stringify(data)).not.toContain(KEY_SECRET);
    }
  );

  it.each([AWS_SECRET, GCP_SECRET])(
    "reports a missing secret in $manager as object_not_found, without the secret's name",
    async (pointer) => {
      vault.getSecretValue.mockRejectedValue(
        new SecretNotFoundError("clickhouse-api-key" as SecretRef)
      );

      const data = await connectorError(() => readApiKey(pointer));

      expect(data.type).toBe("object_not_found");
      expect(data.payload).toEqual({ manager: pointer.manager });
      expect(data.message).toContain(
        "The connector couldn't find its ClickHouse Cloud API key secret in"
      );
      expect(data.message).not.toContain("clickhouse-api-key");
    }
  );

  it.each([
    {
      pointer: AWS_SECRET,
      grant:
        "secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key",
      manager: "AWS Secrets Manager",
    },
    // The shared client reads the version's metadata after its payload.
    {
      pointer: GCP_SECRET,
      grant:
        "secretmanager.versions.access and secretmanager.versions.get on that secret",
      manager: "Google Secret Manager",
    },
  ])(
    "reports a denied read in $pointer.manager as insufficient_privileges, naming what to grant",
    async ({ pointer, grant, manager }) => {
      vault.getSecretValue.mockRejectedValue(
        new UnauthorizedError(pointer.manager)
      );

      await expect(connectorError(() => readApiKey(pointer))).resolves.toEqual({
        type: "insufficient_privileges",
        message: `The connector isn't allowed to read its ClickHouse Cloud API key secret in ${manager}. Grant the connector's identity ${grant}.`,
        payload: { manager: pointer.manager },
      });
    }
  );

  it("lets anything else through as is", async () => {
    const error = new Error("vault exploded");
    vault.getSecretValue.mockRejectedValue(error);

    await expect(readApiKey(AWS_SECRET)).rejects.toBe(error);
  });
});
