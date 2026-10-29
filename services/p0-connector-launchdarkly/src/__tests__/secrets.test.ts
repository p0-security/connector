import {
  type SecretManagerClient,
  SecretNotFoundError,
  type SecretRef,
  type SecretValue,
  type SecretVersionRef,
  UnauthorizedError,
  type VersionMetadata,
} from "@p0security/connector-secret-manager-client";
import type * as secretManagerClient from "@p0security/connector-secret-manager-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { SecretPointer } from "../account.ts";
import { readToken } from "../secrets.ts";
import {
  AWS_SECRET,
  GCP_SECRET,
  NEVER_SHOWN,
  TOKEN,
  connectorError,
  logger,
  recordLogger,
} from "./fixtures.ts";

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factory runs.
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

/** The version every read answers from. The connector reads none of it. */
const VERSION: VersionMetadata = {
  createTime: new Date(0),
  ref: "1" as SecretVersionRef,
  secretRef: AWS_SECRET.secretId as SecretRef,
  state: "enabled",
};

/** What the secret manager answers a read with. Only the value is read. */
const holding = (value: Buffer | string): SecretValue => ({
  value,
  version: VERSION,
});

/** A secret manager client whose reads answer as `vault` says. */
const CLIENT: SecretManagerClient = {
  createSecret: vi.fn(),
  createSecretVersion: vi.fn(),
  deleteSecret: vi.fn(),
  deleteSecretVersion: vi.fn(),
  disableSecretVersion: vi.fn(),
  getAllSecrets: vi.fn(),
  getSecret: vi.fn(),
  getSecretValue: vault.getSecretValue,
  getSecretVersions: vi.fn(),
};

const AWS = {
  pointer: AWS_SECRET,
  name: "AWS Secrets Manager",
  place: "region",
  grant:
    "secretsmanager:GetSecretValue on that secret, and kms:Decrypt on its KMS key if it uses a customer-managed key",
};
const GCP = {
  pointer: GCP_SECRET,
  name: "Google Secret Manager",
  place: "project",
  grant:
    "roles/secretmanager.secretAccessor and roles/secretmanager.viewer on that secret",
};

/** An AWS SDK error: named after the exception, with the request's metadata. */
const awsError = (name: string, httpStatusCode: number) =>
  Object.assign(new Error(`${name} for ${AWS_SECRET.secretId}`), {
    name,
    $metadata: { httpStatusCode, requestId: "aws-request-1" },
  });

const read = (pointer: SecretPointer = AWS_SECRET) =>
  readToken(pointer, logger);

beforeEach(() => {
  vi.clearAllMocks();
  vault.createSecretManagerClient.mockResolvedValue(CLIENT);
  vault.getSecretValue.mockResolvedValue(holding(TOKEN));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("readToken", () => {
  it("reads an AWS secret from the region the pointer names", async () => {
    await expect(read(AWS_SECRET)).resolves.toBe(TOKEN);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "aws",
      region: AWS_SECRET.region,
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({
      ref: AWS_SECRET.secretId,
    });
  });

  // Google returns a secret's value as bytes.
  it("reads a GCP secret, as bytes, from the project the pointer names", async () => {
    vault.getSecretValue.mockResolvedValue(holding(Buffer.from(TOKEN, "utf8")));

    await expect(read(GCP_SECRET)).resolves.toBe(TOKEN);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "gcp",
      projectId: GCP_SECRET.projectId,
    });
  });

  it("reads the secret again on every call", async () => {
    await read();
    vault.getSecretValue.mockResolvedValue(holding("api-rotated"));

    await expect(read()).resolves.toBe("api-rotated");
  });

  // A token pasted with the newline an editor adds would make `fetch` throw
  // an error that quotes the whole header.
  it("drops the whitespace around the token", async () => {
    vault.getSecretValue.mockResolvedValue(holding(`  ${TOKEN}\n`));

    await expect(read()).resolves.toBe(TOKEN);
  });

  it.each([
    ["empty", "", "is empty. Store the access token itself as its value."],
    [
      "a token with a line break in it",
      `${TOKEN}\nX-Other: 1`,
      "doesn't hold an access token: it has spaces, line breaks or other characters a token doesn't have. Store the access token itself as its value, with nothing around it.",
    ],
    [
      "JSON",
      JSON.stringify({ token: TOKEN }, null, 2),
      "doesn't hold an access token: it has spaces, line breaks or other characters a token doesn't have. Store the access token itself as its value, with nothing around it.",
    ],
  ])(
    "refuses a secret that is %s, without quoting it",
    async (_case, value, problem) => {
      vault.getSecretValue.mockResolvedValue(holding(value));

      const error = await connectorError(() => read());

      expect(error.data).toEqual({
        type: "validation_error",
        message: `The secret for the connector's LaunchDarkly access token in AWS Secrets Manager ${problem}`,
        payload: { manager: "aws" },
      });
      expect(JSON.stringify(error.data)).not.toContain(TOKEN);
    }
  );

  it.each([AWS, GCP])(
    "reports a secret $name doesn't find as object_not_found",
    async ({ pointer, name, place }) => {
      vault.getSecretValue.mockRejectedValue(
        new SecretNotFoundError(pointer.secretId as SecretRef)
      );

      const { data } = await connectorError(() => read(pointer));

      expect(data).toEqual({
        type: "object_not_found",
        message: `The connector couldn't find its LaunchDarkly access token's secret, or a value in it, in ${name}. Check the secret's name and ${place} on the LaunchDarkly account in P0, and that the secret exists and holds the access token.`,
        payload: { manager: pointer.manager },
      });
    }
  );

  it.each([AWS, GCP])(
    "reports a read $name refuses as insufficient_privileges, naming what to grant",
    async ({ pointer, name, place, grant }) => {
      vault.getSecretValue.mockRejectedValue(
        new UnauthorizedError(pointer.manager)
      );

      const { data } = await connectorError(() => read(pointer));

      expect(data).toEqual({
        type: "insufficient_privileges",
        message: `The connector isn't allowed to read its LaunchDarkly access token's secret in ${name}. Grant the connector's identity ${grant}. If it has that, check the secret's name and ${place} on the LaunchDarkly account in P0: a secret that doesn't exist can be refused the same way.`,
        payload: { manager: pointer.manager },
      });
    }
  );

  it.each([
    [
      "AWS throttles the call",
      awsError("ThrottlingException", 400),
      "rate_limited",
    ],
    [
      "AWS fails inside",
      awsError("InternalServiceError", 500),
      "upstream_unavailable",
    ],
    ["the failure says nothing about itself", new Error("boom"), "unknown"],
  ] as const)(
    "types any other failure by what it says of itself when %s, and logs it",
    async (_case, failure, type) => {
      const log = recordLogger();
      vault.getSecretValue.mockRejectedValue(failure);

      const { data } = await connectorError(() => read());

      expect(data.type).toBe(type);
      expect(log.lines()).toEqual([
        [
          expect.objectContaining({ manager: "aws" }),
          "reading the access token's secret failed",
        ],
      ]);
    }
  );

  // On AWS the id is any string, so a token pasted where the name goes
  // reaches the connector, and the secret manager's errors repeat what they
  // were given.
  it("shows neither the token nor the pointer, however the read fails", async () => {
    const pasted = { ...AWS_SECRET, secretId: TOKEN };
    const quoting = Object.assign(
      new Error(`failed for ${JSON.stringify(pasted)}`),
      { config: { url: `https://secretsmanager.invalid/?${TOKEN}` } }
    );
    for (const pointer of [AWS_SECRET, GCP_SECRET, pasted] as const) {
      for (const failure of [
        new SecretNotFoundError(pointer.secretId as SecretRef),
        new UnauthorizedError(pointer.manager, { cause: quoting }),
        quoting,
      ]) {
        const log = recordLogger();
        vault.getSecretValue.mockRejectedValue(failure);

        const error = await connectorError(() => read(pointer));

        expect(error.cause).toBeUndefined();
        const seen = log.seen(error, JSON.stringify(error.data));
        for (const marker of NEVER_SHOWN) {
          expect(seen).not.toContain(marker);
        }
      }
    }
  });
});
