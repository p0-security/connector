import { SecretClient } from "@azure/keyvault-secrets";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  NotImplementedError,
  SecretNotFoundError,
  UnauthorizedError,
} from "../../errors.ts";
import type { SecretRef, SecretVersionRef } from "../../types.ts";
import { createKeyVaultSecretManagerClient } from "../keyvault.ts";

const getSecret = vi.fn();
const listPropertiesOfSecrets = vi.fn();
const listPropertiesOfSecretVersions = vi.fn();

vi.mock("@azure/identity", () => ({
  DefaultAzureCredential: vi.fn(),
}));

vi.mock("@azure/keyvault-secrets", () => ({
  SecretClient: vi.fn().mockImplementation(() => ({
    getSecret,
    listPropertiesOfSecrets,
    listPropertiesOfSecretVersions,
  })),
}));

const VAULT_URL = "https://p0-connector-abc123.vault.azure.net";
const SECRET_REF = "my-secret" as SecretRef;
const VERSION_ID = "0123456789abcdef0123456789abcdef";

const restError = (statusCode: number) =>
  Object.assign(new Error(`status ${statusCode}`), {
    name: "RestError",
    statusCode,
  });

const credentialError = (name: string) =>
  Object.assign(new Error(name), { name });

/**
 * A stand-in for the SDK's paged iterator: iterating it walks every page, the
 * way the real one follows each page's `nextLink`. `pagesRead` counts the pages
 * consumed, so a test can tell a full drain from a first-page-only read.
 */
const pagedIterator = <T>(pages: T[][]) => {
  const state = { pagesRead: 0 };
  const iterator = (async function* () {
    for (const page of pages) {
      state.pagesRead++;
      yield* page;
    }
  })();
  return { iterator, state };
};

/** A paged iterator whose first page request fails with `error`. */
const failingIterator = (error: Error) =>
  (async function* () {
    throw error;
  })();

const properties = (name: string, overrides: Record<string, unknown> = {}) => ({
  vaultUrl: VAULT_URL,
  name,
  version: VERSION_ID,
  enabled: true,
  createdOn: new Date("2024-01-01T00:00:00Z"),
  ...overrides,
});

beforeEach(() => {
  getSecret.mockReset();
  listPropertiesOfSecrets.mockReset();
  listPropertiesOfSecretVersions.mockReset();
});

const newClient = () =>
  createKeyVaultSecretManagerClient({ provider: "azure", vaultUrl: VAULT_URL });

type Client = ReturnType<typeof newClient>;

describe("createKeyVaultSecretManagerClient", () => {
  it("binds the SDK client to the configured vault", () => {
    newClient();

    expect(SecretClient).toHaveBeenCalledWith(VAULT_URL, expect.anything());
  });
});

describe("getSecret", () => {
  it("returns the secret's metadata, keyed by its name", async () => {
    getSecret.mockResolvedValue({
      name: "my-secret",
      value: "s3cr3t",
      properties: properties("my-secret"),
    });

    const client = newClient();
    const metadata = await client.getSecret({ ref: SECRET_REF });

    expect(metadata).toEqual({
      ref: SECRET_REF,
      name: "my-secret",
      createTime: new Date("2024-01-01T00:00:00Z"),
    });
    expect(getSecret).toHaveBeenCalledWith("my-secret");
  });

  it("throws SecretNotFoundError on a 404", async () => {
    getSecret.mockRejectedValue(restError(404));

    const client = newClient();
    await expect(client.getSecret({ ref: SECRET_REF })).rejects.toThrow(
      SecretNotFoundError
    );
  });

  it.each([401, 403])("throws UnauthorizedError on a %d", async (status) => {
    getSecret.mockRejectedValue(restError(status));

    const client = newClient();
    await expect(client.getSecret({ ref: SECRET_REF })).rejects.toThrow(
      UnauthorizedError
    );
  });
});

describe("getAllSecrets", () => {
  it("accumulates secrets across pages", async () => {
    const { iterator, state } = pagedIterator([
      [properties("a")],
      [properties("b", { createdOn: new Date("2024-01-02T00:00:00Z") })],
    ]);
    listPropertiesOfSecrets.mockReturnValue(iterator);

    const client = newClient();
    const secrets = await client.getAllSecrets();

    expect(secrets).toEqual([
      {
        ref: "a",
        name: "a",
        createTime: new Date("2024-01-01T00:00:00Z"),
      },
      {
        ref: "b",
        name: "b",
        createTime: new Date("2024-01-02T00:00:00Z"),
      },
    ]);
    expect(state.pagesRead).toBe(2);
  });

  it("throws UnauthorizedError on a 403", async () => {
    listPropertiesOfSecrets.mockReturnValue(failingIterator(restError(403)));

    const client = newClient();
    await expect(client.getAllSecrets()).rejects.toThrow(UnauthorizedError);
  });
});

describe("getSecretVersions", () => {
  it("maps each version's enabled flag onto SecretVersionState, across pages", async () => {
    const { iterator } = pagedIterator([
      [properties("my-secret", { version: "v1", enabled: false })],
      [
        properties("my-secret", {
          version: "v2",
          createdOn: new Date("2024-01-02T00:00:00Z"),
        }),
      ],
    ]);
    listPropertiesOfSecretVersions.mockReturnValue(iterator);

    const client = newClient();
    const versions = await client.getSecretVersions({ ref: SECRET_REF });

    expect(versions).toEqual([
      {
        ref: "my-secret/versions/v1",
        secretRef: SECRET_REF,
        state: "disabled",
        createTime: new Date("2024-01-01T00:00:00Z"),
      },
      {
        ref: "my-secret/versions/v2",
        secretRef: SECRET_REF,
        state: "enabled",
        createTime: new Date("2024-01-02T00:00:00Z"),
      },
    ]);
    expect(listPropertiesOfSecretVersions).toHaveBeenCalledWith("my-secret");
  });

  it("throws SecretNotFoundError on a 404", async () => {
    listPropertiesOfSecretVersions.mockReturnValue(
      failingIterator(restError(404))
    );

    const client = newClient();
    await expect(client.getSecretVersions({ ref: SECRET_REF })).rejects.toThrow(
      SecretNotFoundError
    );
  });
});

describe("getSecretValue", () => {
  it("returns the value and metadata of the current version", async () => {
    getSecret.mockResolvedValue({
      name: "my-secret",
      value: "s3cr3t",
      properties: properties("my-secret"),
    });

    const client = newClient();
    const result = await client.getSecretValue({ ref: SECRET_REF });

    expect(result).toEqual({
      value: "s3cr3t",
      version: {
        ref: `my-secret/versions/${VERSION_ID}`,
        secretRef: SECRET_REF,
        state: "enabled",
        createTime: new Date("2024-01-01T00:00:00Z"),
      },
    });
    expect(getSecret).toHaveBeenCalledWith("my-secret");
  });

  it("throws when the version has no value", async () => {
    getSecret.mockResolvedValue({
      name: "my-secret",
      properties: properties("my-secret"),
    });

    const client = newClient();
    await expect(client.getSecretValue({ ref: SECRET_REF })).rejects.toThrow(
      /no value/i
    );
  });

  it("throws SecretNotFoundError on a 404", async () => {
    getSecret.mockRejectedValue(restError(404));

    const client = newClient();
    await expect(client.getSecretValue({ ref: SECRET_REF })).rejects.toThrow(
      SecretNotFoundError
    );
  });

  it.each([401, 403])("throws UnauthorizedError on a %d", async (status) => {
    getSecret.mockRejectedValue(restError(status));

    const client = newClient();
    await expect(client.getSecretValue({ ref: SECRET_REF })).rejects.toThrow(
      UnauthorizedError
    );
  });

  it.each([
    "AggregateAuthenticationError",
    "AuthenticationError",
    "CredentialUnavailableError",
  ])("throws UnauthorizedError on %s", async (errorName) => {
    getSecret.mockRejectedValue(credentialError(errorName));

    const client = newClient();
    await expect(client.getSecretValue({ ref: SECRET_REF })).rejects.toThrow(
      UnauthorizedError
    );
  });

  it("rethrows other errors unchanged", async () => {
    const error = restError(500);
    getSecret.mockRejectedValue(error);

    const client = newClient();
    await expect(client.getSecretValue({ ref: SECRET_REF })).rejects.toBe(
      error
    );
  });
});

describe("write methods", () => {
  const versionRef = `my-secret/versions/${VERSION_ID}` as SecretVersionRef;

  it.each([
    ["createSecret", (c: Client) => c.createSecret({ name: "my-secret" })],
    ["deleteSecret", (c: Client) => c.deleteSecret({ ref: SECRET_REF })],
    [
      "createSecretVersion",
      (c: Client) =>
        c.createSecretVersion({ ref: SECRET_REF, type: "random", bytes: 32 }),
    ],
    [
      "disableSecretVersion",
      (c: Client) => c.disableSecretVersion({ ref: versionRef }),
    ],
    [
      "deleteSecretVersion",
      (c: Client) => c.deleteSecretVersion({ ref: versionRef }),
    ],
  ])("rejects %s with NotImplementedError", async (_, call) => {
    await expect(call(newClient())).rejects.toThrow(NotImplementedError);
  });
});
