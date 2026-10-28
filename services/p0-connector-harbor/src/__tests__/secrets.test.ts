import {
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
} from "@p0security/secret-manager-client";
import type * as secretManagerClient from "@p0security/secret-manager-client";
import { inspect } from "node:util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { SecretPointer } from "../accesses/project-role/definition.ts";
import { readAdminCredential } from "../secrets.ts";
import {
  ADMIN_CREDENTIAL,
  AWS_SECRET,
  GCP_SECRET,
  NEVER_SHOWN,
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

vi.mock("@p0security/secret-manager-client", async (importOriginal) => ({
  ...(await importOriginal<typeof secretManagerClient>()),
  createSecretManagerClient: vault.createSecretManagerClient,
}));

// The admin credential, as the customer stores it.
const STORED = JSON.stringify(ADMIN_CREDENTIAL);

/** What the secret manager answers a read with. Only the value is read. */
const holding = (value: Buffer | string) =>
  ({ value }) as secretManagerClient.SecretValue;

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

// The request a vendor's error carries, which names the secret.
const REQUEST_URL = `https://secretmanager.googleapis.com/v1/projects/${GCP_SECRET.projectId}/secrets/${GCP_SECRET.secretId}/versions/latest:access`;

/** An AWS SDK error: named after the exception, with the request's metadata. */
const awsError = (name: string, httpStatusCode: number) =>
  Object.assign(new Error(`${name} for ${AWS_SECRET.secretId}`), {
    name,
    $fault: "client",
    $metadata: { httpStatusCode, requestId: "aws-request-1", attempts: 3 },
  });

/** An error of Google's client, as gaxios 7 shapes it: a bare `Error` with the status and the request. */
const googleError = (status: number) =>
  Object.assign(new Error(`boom at ${REQUEST_URL}`), {
    config: { url: new URL(REQUEST_URL), headers: {} },
    response: { status, config: { url: new URL(REQUEST_URL) }, data: {} },
    code: undefined,
    status,
  });

/** A call that never reached the secret manager, as Node reports it. */
const networkError = (code: string) =>
  Object.assign(new Error(`${code} ${REQUEST_URL}`), { code });

const read = (pointer: SecretPointer = AWS_SECRET) =>
  readAdminCredential(pointer, logger);

beforeEach(() => {
  vi.clearAllMocks();
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  } as Partial<secretManagerClient.SecretManagerClient> as secretManagerClient.SecretManagerClient);
  vault.getSecretValue.mockResolvedValue(holding(STORED));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("readAdminCredential", () => {
  it("reads an AWS secret from the region the pointer names", async () => {
    await read(AWS_SECRET);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "aws",
      region: AWS_SECRET.region,
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({
      ref: AWS_SECRET.secretId,
    });
  });

  it("reads a GCP secret from the project the pointer names", async () => {
    await read(GCP_SECRET);

    expect(vault.createSecretManagerClient).toHaveBeenCalledWith({
      provider: "gcp",
      projectId: GCP_SECRET.projectId,
    });
    expect(vault.getSecretValue).toHaveBeenCalledWith({
      ref: GCP_SECRET.secretId,
    });
  });

  // Google returns a secret's value as bytes.
  it("decodes a secret that arrives as bytes", async () => {
    vault.getSecretValue.mockResolvedValue(
      holding(Buffer.from(STORED, "utf8"))
    );
    await expect(read(GCP_SECRET)).resolves.toStrictEqual(ADMIN_CREDENTIAL);
  });

  it("reads the secret again on every call", async () => {
    await read();
    vault.getSecretValue.mockResolvedValue(
      holding(JSON.stringify({ ...ADMIN_CREDENTIAL, refreshToken: "rotated" }))
    );

    await expect(read()).resolves.toStrictEqual({
      ...ADMIN_CREDENTIAL,
      refreshToken: "rotated",
    });
  });

  it("logs nothing when the read works", async () => {
    const log = recordLogger();
    await read();
    expect(log.lines()).toHaveLength(0);
  });

  // A secret with no value yet is answered as not found too.
  it.each([AWS, GCP])(
    "reports a secret $name doesn't find as object_not_found",
    async ({ pointer, name, place }) => {
      vault.getSecretValue.mockRejectedValue(
        new SecretNotFoundError(pointer.secretId as SecretRef)
      );

      const { data } = await connectorError(() => read(pointer));

      expect(data.type).toBe("object_not_found");
      expect(data.payload).toEqual({ manager: pointer.manager });
      expect(data.message).toBe(
        `The connector couldn't find its Harbor admin credential's secret, or a value in it, in ${name}. Check the secret's name and ${place} on the Harbor instance in P0, and that the secret exists and holds the admin credential's JSON.`
      );
    }
  );

  // With a grant on the one secret, a name that doesn't exist is refused
  // like one the connector may not read, so the message covers both.
  it.each([AWS, GCP])(
    "reports a read $name refuses as insufficient_privileges, naming what to grant",
    async ({ pointer, name, place, grant }) => {
      vault.getSecretValue.mockRejectedValue(
        new UnauthorizedError(pointer.manager)
      );

      const { data } = await connectorError(() => read(pointer));

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({ manager: pointer.manager });
      expect(data.message).toBe(
        `The connector isn't allowed to read its Harbor admin credential's secret in ${name}. Grant the connector's identity ${grant}. If it has that, check the secret's name and ${place} on the Harbor instance in P0: a secret that doesn't exist can be refused the same way.`
      );
    }
  );

  describe("any other failure", () => {
    // [what failed, on which cloud, the failure, its type, how the message describes it, what the log line holds]
    const FAILURES = [
      [
        "AWS throttles the call",
        AWS,
        awsError("ThrottlingException", 400),
        "rate_limited",
        ": ThrottlingException, HTTP 400",
        {
          name: "ThrottlingException",
          status: 400,
          requestId: "aws-request-1",
        },
      ],
      [
        "AWS fails inside",
        AWS,
        awsError("InternalServiceError", 500),
        "upstream_unavailable",
        ": InternalServiceError, HTTP 500",
        {
          name: "InternalServiceError",
          status: 500,
          requestId: "aws-request-1",
        },
      ],
      [
        "AWS refuses the request as invalid",
        AWS,
        awsError("InvalidRequestException", 400),
        "unknown",
        ": InvalidRequestException, HTTP 400",
        {
          name: "InvalidRequestException",
          status: 400,
          requestId: "aws-request-1",
        },
      ],
      [
        "the region doesn't resolve",
        AWS,
        networkError("ENOTFOUND"),
        "upstream_unavailable",
        ": ENOTFOUND",
        { code: "ENOTFOUND" },
      ],
      [
        "the connection is reset",
        AWS,
        networkError("ECONNRESET"),
        "upstream_unavailable",
        ": ECONNRESET",
        { code: "ECONNRESET" },
      ],
      [
        "Google limits the call",
        GCP,
        googleError(429),
        "rate_limited",
        ": HTTP 429",
        { status: 429 },
      ],
      [
        "Google is unavailable",
        GCP,
        googleError(503),
        "upstream_unavailable",
        ": HTTP 503",
        { status: 503 },
      ],
      [
        "Google refuses the request as invalid",
        GCP,
        googleError(400),
        "unknown",
        ": HTTP 400",
        { status: 400 },
      ],
      [
        "Google can't be resolved",
        GCP,
        networkError("EAI_AGAIN"),
        "upstream_unavailable",
        ": EAI_AGAIN",
        { code: "EAI_AGAIN" },
      ],
      [
        "the failure says nothing about itself",
        AWS,
        new Error(`no string or binary value for "${AWS_SECRET.secretId}"`),
        "unknown",
        "",
        {},
      ],
      ["what is thrown isn't an error", GCP, REQUEST_URL, "unknown", "", {}],
    ] as const;

    it.each(FAILURES)(
      "is typed and described by what it says of itself when %s",
      async (_case, cloud, failure, type, description) => {
        vault.getSecretValue.mockRejectedValue(failure);

        const { data } = await connectorError(() => read(cloud.pointer));

        expect(data.type).toBe(type);
        expect(data.payload).toEqual({ manager: cloud.pointer.manager });
        expect(data.message).toBe(
          `The connector couldn't read its Harbor admin credential's secret in ${cloud.name}${description}. Check the secret's ${cloud.place} on the Harbor instance in P0, and try again.`
        );
      }
    );

    // The error P0 gets is a sentence. The log line is what's left for
    // whoever has to find out why.
    it.each(FAILURES)(
      "is logged with what is safe to log when %s",
      async (_case, cloud, failure, _type, _description, facts) => {
        const log = recordLogger();
        vault.getSecretValue.mockRejectedValue(failure);

        await connectorError(() => read(cloud.pointer));

        expect(log.lines()).toEqual([
          [
            { manager: cloud.pointer.manager, ...facts },
            "reading the admin credential's secret failed",
          ],
        ]);
      }
    );

    // Google's client is built from the connector's own credentials, which
    // can be missing.
    it("covers a secret manager the connector can't connect to", async () => {
      vault.createSecretManagerClient.mockRejectedValue(
        new Error("Could not load the default credentials")
      );

      const { data } = await connectorError(() => read(GCP_SECRET));

      expect(data.type).toBe("unknown");
      expect(data.message).toBe(
        "The connector couldn't read its Harbor admin credential's secret in Google Secret Manager. Check the secret's project on the Harbor instance in P0, and try again."
      );
    });
  });

  // The client wraps the vendor's error in the two it maps.
  it("logs the vendor's request id for a failure the client mapped", async () => {
    const log = recordLogger();
    vault.getSecretValue.mockRejectedValue(
      new UnauthorizedError("aws", {
        cause: awsError("AccessDeniedException", 400),
      })
    );

    await connectorError(() => read());

    expect(log.lines()).toEqual([
      [
        {
          manager: "aws",
          name: "AccessDeniedException",
          status: 400,
          requestId: "aws-request-1",
        },
        "reading the admin credential's secret failed",
      ],
    ]);
  });

  describe("what a failure may not show", () => {
    // On AWS the id is any string, so a credential pasted where the name
    // goes reaches the connector, and the secret manager's errors repeat
    // what they were given: in their message, or in the vendor's error they
    // carry as their cause.
    const PASTED = { ...AWS_SECRET, secretId: STORED };
    const quoting = (pointer: SecretPointer) =>
      Object.assign(new Error(`failed for ${JSON.stringify(pointer)}`), {
        config: { url: `${REQUEST_URL}?${JSON.stringify(pointer)}` },
      });

    it.each([
      ["AWS", AWS_SECRET],
      ["GCP", GCP_SECRET],
      ["AWS, with a credential pasted as the id,", PASTED],
    ] as const)(
      "is the pointer, on %s, however the read fails",
      async (_case, pointer) => {
        const log = recordLogger();
        for (const failure of [
          new SecretNotFoundError(pointer.secretId as SecretRef),
          new UnauthorizedError(pointer.manager, { cause: quoting(pointer) }),
          quoting(pointer),
        ]) {
          vault.getSecretValue.mockRejectedValue(failure);

          const error = await connectorError(() => read(pointer));

          expect(error.cause).toBeUndefined();
          const seen = log.seen(error, JSON.stringify(error.data));
          for (const marker of NEVER_SHOWN) {
            expect(seen).not.toContain(marker);
          }
        }
      }
    );
  });
});

describe("readAdminCredential's parse", () => {
  const ADMIN = ADMIN_CREDENTIAL;

  const readAdmin = (pointer: SecretPointer = AWS_SECRET) =>
    readAdminCredential(pointer, logger);

  beforeEach(() => {
    vault.getSecretValue.mockResolvedValue(holding(JSON.stringify(ADMIN)));
  });

  it("reads the credential from the secret the pointer names, on every call", async () => {
    await expect(readAdmin()).resolves.toStrictEqual(ADMIN);
    await readAdmin(GCP_SECRET);
    expect(vault.getSecretValue.mock.calls).toEqual([
      [{ ref: AWS_SECRET.secretId }],
      [{ ref: GCP_SECRET.secretId }],
    ]);
  });

  it("refuses a secret that isn't the credential, naming the fields and no value", async () => {
    vault.getSecretValue.mockResolvedValue(
      holding(JSON.stringify({ ...ADMIN, refreshToken: "", client_id: "x" }))
    );
    const error = await connectorError(() => readAdmin());
    expect(error.data).toEqual({
      type: "validation_error",
      message:
        'The secret for the Harbor admin credential in AWS Secrets Manager isn\'t the JSON the connector expects: refreshToken is missing or not valid, and it has fields besides issuer, clientId, clientSecret and refreshToken. Store {"issuer": "<OIDC issuer URL>", "clientId": "<Harbor\'s OIDC client ID>", "clientSecret": "<client secret>", "refreshToken": "<refresh token>"} as its value.',
      payload: { manager: "aws" },
    });
    expect(inspect(error)).not.toContain("SENTINEL");
  });

  it("refuses a secret that isn't JSON", async () => {
    vault.getSecretValue.mockResolvedValue(holding("SENTINEL not json"));
    const error = await connectorError(() => readAdmin());
    expect(error.data.message).toContain(
      "isn't the JSON the connector expects: it isn't a JSON object."
    );
    expect(inspect(error)).not.toContain("SENTINEL");
  });

  it.each([AWS, GCP])(
    "names the admin credential's secret when $name doesn't find it",
    async ({ pointer, name, place }) => {
      vault.getSecretValue.mockRejectedValue(
        new SecretNotFoundError(pointer.secretId as SecretRef)
      );
      const log = recordLogger();
      const { data } = await connectorError(() => readAdmin(pointer));
      expect(data.message).toBe(
        `The connector couldn't find its Harbor admin credential's secret, or a value in it, in ${name}. Check the secret's name and ${place} on the Harbor instance in P0, and that the secret exists and holds the admin credential's JSON.`
      );
      expect(log.lines()).toContainEqual([
        expect.objectContaining({ manager: pointer.manager }),
        "reading the admin credential's secret failed",
      ]);
    }
  );

  it("names the admin credential's secret when the read is refused", async () => {
    vault.getSecretValue.mockRejectedValue(new UnauthorizedError("aws"));
    const { data } = await connectorError(() => readAdmin());
    expect(data.type).toBe("insufficient_privileges");
    expect(data.message).toContain(
      "The connector isn't allowed to read its Harbor admin credential's secret in AWS Secrets Manager."
    );
  });
});
