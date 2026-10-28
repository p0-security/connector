import {
  CreateSecretCommand,
  DeleteSecretCommand,
  DescribeSecretCommand,
  GetSecretValueCommand,
  ListSecretVersionIdsCommand,
  ListSecretsCommand,
  PutSecretValueCommand,
  UpdateSecretVersionStageCommand,
} from "@aws-sdk/client-secrets-manager";
import type * as SecretsManager from "@aws-sdk/client-secrets-manager";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  SecretAlreadyExistsError,
  SecretNotFoundError,
  SecretVersionNotFoundError,
  UnauthorizedError,
} from "../../errors.ts";
import type { SecretRef, SecretVersionRef } from "../../types.ts";
import { createAwsSecretManagerClient } from "../aws.ts";

const send = vi.fn();

vi.mock("@aws-sdk/client-secrets-manager", async (importOriginal) => {
  const actual = await importOriginal<typeof SecretsManager>();
  return {
    ...actual,
    SecretsManagerClient: vi.fn().mockImplementation(() => ({ send })),
  };
});

const REGION = "us-east-1";
const SECRET_REF =
  "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-abcdef" as SecretRef;

const awsError = (name: string) => Object.assign(new Error(name), { name });

beforeEach(() => {
  send.mockReset();
});

const newClient = () =>
  createAwsSecretManagerClient({ provider: "aws", region: REGION });

describe("createSecret", () => {
  it("creates the secret with no initial version", async () => {
    send.mockImplementation((command) => {
      if (command instanceof CreateSecretCommand) {
        return Promise.resolve({ ARN: SECRET_REF, Name: "my-secret" });
      }
      if (command instanceof DescribeSecretCommand) {
        return Promise.resolve({
          ARN: SECRET_REF,
          Name: "my-secret",
          CreatedDate: new Date("2024-01-01T00:00:00Z"),
        });
      }
      throw new Error("unexpected command");
    });

    const client = newClient();
    const metadata = await client.createSecret({ name: "my-secret" });

    expect(metadata).toEqual({
      ref: SECRET_REF,
      name: "my-secret",
      createTime: new Date("2024-01-01T00:00:00Z"),
    });
    expect(send.mock.calls[0]?.[0].input).toEqual({ Name: "my-secret" });
  });

  it("throws SecretAlreadyExistsError on ResourceExistsException", async () => {
    send.mockRejectedValue(awsError("ResourceExistsException"));

    const client = newClient();
    await expect(client.createSecret({ name: "my-secret" })).rejects.toThrow(
      SecretAlreadyExistsError
    );
  });

  it.each([
    "AccessDeniedException",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "NotAuthorized",
  ])("throws UnauthorizedError on %s", async (errorName) => {
    send.mockRejectedValue(awsError(errorName));

    const client = newClient();
    await expect(client.createSecret({ name: "my-secret" })).rejects.toThrow(
      UnauthorizedError
    );
  });

  it("retries the post-create DescribeSecret lookup through transient ResourceNotFoundException", async () => {
    let describeAttempts = 0;
    send.mockImplementation((command) => {
      if (command instanceof CreateSecretCommand) {
        return Promise.resolve({ ARN: SECRET_REF, Name: "my-secret" });
      }
      if (command instanceof DescribeSecretCommand) {
        describeAttempts++;
        if (describeAttempts < 3) {
          return Promise.reject(awsError("ResourceNotFoundException"));
        }
        return Promise.resolve({
          ARN: SECRET_REF,
          Name: "my-secret",
          CreatedDate: new Date("2024-01-01T00:00:00Z"),
        });
      }
      throw new Error("unexpected command");
    });

    const client = newClient();
    const metadata = await client.createSecret({ name: "my-secret" });

    expect(metadata.ref).toBe(SECRET_REF);
    expect(describeAttempts).toBe(3);
  });

  it("gives up after exhausting DescribeSecret retries", async () => {
    send.mockImplementation((command) => {
      if (command instanceof CreateSecretCommand) {
        return Promise.resolve({ ARN: SECRET_REF, Name: "my-secret" });
      }
      if (command instanceof DescribeSecretCommand) {
        return Promise.reject(awsError("ResourceNotFoundException"));
      }
      throw new Error("unexpected command");
    });

    const client = newClient();
    await expect(client.createSecret({ name: "my-secret" })).rejects.toThrow(
      /ResourceNotFoundException/
    );
  });
});

describe("deleteSecret", () => {
  it("force-deletes the secret with no recovery window", async () => {
    send.mockResolvedValue({});

    const client = newClient();
    await client.deleteSecret({ ref: SECRET_REF });

    expect(send).toHaveBeenCalledTimes(1);
    const command = send.mock.calls[0]?.[0];
    expect(command).toBeInstanceOf(DeleteSecretCommand);
    expect(command.input).toEqual({
      SecretId: SECRET_REF,
      ForceDeleteWithoutRecovery: true,
    });
  });

  it("throws SecretNotFoundError on a ResourceNotFoundException", async () => {
    send.mockRejectedValue(awsError("ResourceNotFoundException"));

    const client = newClient();
    await expect(client.deleteSecret({ ref: SECRET_REF })).rejects.toThrow(
      SecretNotFoundError
    );
  });

  it.each([
    "AccessDeniedException",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "NotAuthorized",
  ])("throws UnauthorizedError on %s", async (errorName) => {
    send.mockRejectedValue(awsError(errorName));

    const client = newClient();
    await expect(client.deleteSecret({ ref: SECRET_REF })).rejects.toThrow(
      UnauthorizedError
    );
  });
});

describe("getAllSecrets", () => {
  it("accumulates secrets across pages", async () => {
    send
      .mockImplementationOnce(() =>
        Promise.resolve({
          SecretList: [
            {
              ARN: `${SECRET_REF}-a`,
              Name: "a",
              CreatedDate: new Date("2024-01-01T00:00:00Z"),
            },
          ],
          NextToken: "page-2",
        })
      )
      .mockImplementationOnce(() =>
        Promise.resolve({
          SecretList: [
            {
              ARN: `${SECRET_REF}-b`,
              Name: "b",
              CreatedDate: new Date("2024-01-02T00:00:00Z"),
            },
          ],
          NextToken: undefined,
        })
      );

    const client = newClient();
    const secrets = await client.getAllSecrets();

    expect(secrets.map((s) => s.name)).toEqual(["a", "b"]);
    expect(send.mock.calls[0]?.[0]).toBeInstanceOf(ListSecretsCommand);
    expect(send.mock.calls[0]?.[0].input).toEqual({ NextToken: undefined });
    expect(send.mock.calls[1]?.[0].input).toEqual({ NextToken: "page-2" });
  });
});

describe("getSecretVersions", () => {
  it("maps staging labels onto SecretVersionState", async () => {
    send.mockResolvedValue({
      Versions: [
        {
          VersionId: "v1",
          VersionStages: [],
          CreatedDate: new Date("2024-01-01T00:00:00Z"),
        },
        {
          VersionId: "v2",
          VersionStages: ["AWSCURRENT"],
          CreatedDate: new Date("2024-01-02T00:00:00Z"),
        },
      ],
      NextToken: undefined,
    });

    const client = newClient();
    const versions = await client.getSecretVersions({ ref: SECRET_REF });

    expect(versions).toEqual([
      {
        ref: `${SECRET_REF}/versions/v1`,
        secretRef: SECRET_REF,
        state: "disabled",
        createTime: new Date("2024-01-01T00:00:00Z"),
      },
      {
        ref: `${SECRET_REF}/versions/v2`,
        secretRef: SECRET_REF,
        state: "enabled",
        createTime: new Date("2024-01-02T00:00:00Z"),
      },
    ]);
    expect(send.mock.calls[0]?.[0].input).toEqual({
      SecretId: SECRET_REF,
      IncludeDeprecated: true,
      NextToken: undefined,
    });
  });

  it("throws SecretNotFoundError on a ResourceNotFoundException", async () => {
    send.mockRejectedValue(awsError("ResourceNotFoundException"));

    const client = newClient();
    await expect(
      client.getSecretVersions({
        ref: "arn:aws:secretsmanager:us-east-1:123456789012:secret:missing" as SecretRef,
      })
    ).rejects.toThrow(SecretNotFoundError);
  });
});

describe("getSecretValue", () => {
  const VERSION_ID = "33333333-3333-3333-3333-333333333333";

  it("returns the SecretString and metadata of the current version", async () => {
    send.mockImplementation((command) => {
      if (command instanceof GetSecretValueCommand) {
        return Promise.resolve({
          SecretString: "s3cr3t",
          VersionId: VERSION_ID,
          VersionStages: ["AWSCURRENT"],
          CreatedDate: new Date("2024-01-01T00:00:00Z"),
        });
      }
      throw new Error("unexpected command");
    });

    const client = newClient();
    const result = await client.getSecretValue({ ref: SECRET_REF });

    expect(result).toEqual({
      value: "s3cr3t",
      version: {
        ref: `${SECRET_REF}/versions/${VERSION_ID}`,
        secretRef: SECRET_REF,
        state: "enabled",
        createTime: new Date("2024-01-01T00:00:00Z"),
      },
    });
    const command = send.mock.calls[0]?.[0];
    expect(command).toBeInstanceOf(GetSecretValueCommand);
    expect(command.input).toEqual({ SecretId: SECRET_REF });
  });

  it("returns the SecretBinary of the current version as a Buffer", async () => {
    const binary = new Uint8Array([1, 2, 3, 4]);
    send.mockImplementation((command) => {
      if (command instanceof GetSecretValueCommand) {
        return Promise.resolve({
          SecretBinary: binary,
          VersionId: VERSION_ID,
          VersionStages: ["AWSCURRENT"],
          CreatedDate: new Date("2024-01-02T00:00:00Z"),
        });
      }
      throw new Error("unexpected command");
    });

    const client = newClient();
    const result = await client.getSecretValue({ ref: SECRET_REF });

    expect(Buffer.isBuffer(result.value)).toBe(true);
    expect(result.value).toEqual(Buffer.from(binary));
    expect(result.version.ref).toBe(`${SECRET_REF}/versions/${VERSION_ID}`);
  });

  it("throws when the version has neither a string nor a binary payload", async () => {
    send.mockResolvedValue({ VersionId: VERSION_ID });

    const client = newClient();
    await expect(client.getSecretValue({ ref: SECRET_REF })).rejects.toThrow(
      /no string or binary/i
    );
  });

  it("throws SecretNotFoundError on a ResourceNotFoundException", async () => {
    send.mockRejectedValue(awsError("ResourceNotFoundException"));

    const client = newClient();
    await expect(client.getSecretValue({ ref: SECRET_REF })).rejects.toThrow(
      SecretNotFoundError
    );
  });

  it.each([
    "AccessDeniedException",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "NotAuthorized",
  ])("throws UnauthorizedError on %s", async (errorName) => {
    send.mockRejectedValue(awsError(errorName));

    const client = newClient();
    await expect(client.getSecretValue({ ref: SECRET_REF })).rejects.toThrow(
      UnauthorizedError
    );
  });
});

describe("createSecretVersion", () => {
  const versionId = "11111111-1111-1111-1111-111111111111";

  it("adds a version with a 32-byte random binary payload", async () => {
    send.mockResolvedValue({
      ARN: SECRET_REF,
      Name: "my-secret",
      VersionId: versionId,
    });

    const client = newClient();
    const metadata = await client.createSecretVersion({
      ref: SECRET_REF,
      type: "random",
      bytes: 32,
    });

    expect(metadata.ref).toBe(`${SECRET_REF}/versions/${versionId}`);
    expect(send).toHaveBeenCalledTimes(1);
    const command = send.mock.calls[0]?.[0];
    expect(command).toBeInstanceOf(PutSecretValueCommand);
    expect(command.input.SecretId).toBe(SECRET_REF);
    expect(command.input.SecretBinary).toHaveLength(32);
  });

  it("adds a version with an explicit value payload", async () => {
    send.mockResolvedValue({
      ARN: SECRET_REF,
      Name: "my-secret",
      VersionId: versionId,
    });

    const client = newClient();
    const value = Buffer.from("my-secret-value");
    const metadata = await client.createSecretVersion({
      ref: SECRET_REF,
      type: "value",
      value,
    });

    expect(metadata.ref).toBe(`${SECRET_REF}/versions/${versionId}`);
    expect(send).toHaveBeenCalledTimes(1);
    const command = send.mock.calls[0]?.[0];
    expect(command).toBeInstanceOf(PutSecretValueCommand);
    expect(command.input.SecretId).toBe(SECRET_REF);
    expect(command.input.SecretBinary).toBe(value);
  });

  it("throws SecretNotFoundError on a ResourceNotFoundException", async () => {
    send.mockRejectedValue(awsError("ResourceNotFoundException"));

    const client = newClient();
    await expect(
      client.createSecretVersion({ ref: SECRET_REF, type: "random", bytes: 32 })
    ).rejects.toThrow(SecretNotFoundError);
  });
});

describe("disableSecretVersion", () => {
  const versionId = "11111111-1111-1111-1111-111111111111";
  const ref = `${SECRET_REF}/versions/${versionId}` as SecretVersionRef;

  it("removes every staging label attached to the version", async () => {
    send.mockImplementation((command) => {
      if (command instanceof ListSecretVersionIdsCommand) {
        return Promise.resolve({
          Versions: [
            {
              VersionId: versionId,
              VersionStages: ["AWSCURRENT", "CUSTOM"],
              CreatedDate: new Date("2024-01-01T00:00:00Z"),
            },
          ],
          NextToken: undefined,
        });
      }
      if (command instanceof UpdateSecretVersionStageCommand) {
        return Promise.resolve({});
      }
      throw new Error("unexpected command");
    });

    const client = newClient();
    await client.disableSecretVersion({ ref });

    const updateInputs = send.mock.calls
      .map(([command]) => command)
      .filter((command) => command instanceof UpdateSecretVersionStageCommand)
      .map((command) => command.input);
    expect(updateInputs).toEqual([
      {
        SecretId: SECRET_REF,
        VersionStage: "AWSCURRENT",
        RemoveFromVersionId: versionId,
      },
      {
        SecretId: SECRET_REF,
        VersionStage: "CUSTOM",
        RemoveFromVersionId: versionId,
      },
    ]);
  });

  it("throws SecretVersionNotFoundError when the version doesn't exist", async () => {
    send.mockResolvedValue({ Versions: [], NextToken: undefined });

    const client = newClient();
    await expect(client.disableSecretVersion({ ref })).rejects.toThrow(
      SecretVersionNotFoundError
    );
  });
});

describe("deleteSecretVersion", () => {
  it("removes every staging label, same as disableSecretVersion, since AWS has no per-version hard delete", async () => {
    const versionId = "22222222-2222-2222-2222-222222222222";
    const ref = `${SECRET_REF}/versions/${versionId}` as SecretVersionRef;

    send.mockImplementation((command) => {
      if (command instanceof ListSecretVersionIdsCommand) {
        return Promise.resolve({
          Versions: [
            {
              VersionId: versionId,
              VersionStages: ["AWSPREVIOUS"],
              CreatedDate: new Date("2024-01-01T00:00:00Z"),
            },
          ],
          NextToken: undefined,
        });
      }
      if (command instanceof UpdateSecretVersionStageCommand) {
        return Promise.resolve({});
      }
      throw new Error("unexpected command");
    });

    const client = newClient();
    await client.deleteSecretVersion({ ref });

    const updateCommand = send.mock.calls
      .map(([command]) => command)
      .find((command) => command instanceof UpdateSecretVersionStageCommand);
    expect(updateCommand?.input).toEqual({
      SecretId: SECRET_REF,
      VersionStage: "AWSPREVIOUS",
      RemoveFromVersionId: versionId,
    });
  });

  it("throws SecretVersionNotFoundError when the version doesn't exist", async () => {
    const ref = `${SECRET_REF}/versions/missing` as SecretVersionRef;
    send.mockResolvedValue({ Versions: [], NextToken: undefined });

    const client = newClient();
    await expect(client.deleteSecretVersion({ ref })).rejects.toThrow(
      SecretVersionNotFoundError
    );
  });
});
