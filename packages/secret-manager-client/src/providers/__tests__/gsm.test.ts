import { createClients } from "@p0security/connector-gcloud-common";
import type { Mock } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  SecretAlreadyExistsError,
  SecretNotFoundError,
  SecretVersionNotFoundError,
  UnauthorizedError,
} from "../../errors.ts";
import type { SecretRef, SecretVersionRef } from "../../types.ts";
import { createGsmSecretManagerClient } from "../gsm.ts";

vi.mock("@p0security/connector-gcloud-common", () => ({
  createClients: vi.fn(),
}));

const createFakeSecretManager = () => ({
  projects: {
    secrets: {
      create: vi.fn(),
      get: vi.fn(),
      delete: vi.fn(),
      list: vi.fn(),
      addVersion: vi.fn(),
      versions: {
        list: vi.fn(),
        access: vi.fn(),
        get: vi.fn(),
        disable: vi.fn(),
        destroy: vi.fn(),
      },
    },
  },
});

type FakeSecretManager = ReturnType<typeof createFakeSecretManager>;

const PROJECT_ID = "test-project";

let secretManager: FakeSecretManager;

beforeEach(() => {
  secretManager = createFakeSecretManager();
  (createClients as Mock).mockResolvedValue({ secretManager });
});

const newClient = () =>
  createGsmSecretManagerClient({ provider: "gcp", projectId: PROJECT_ID });

describe("createSecret", () => {
  it("creates the secret with no initial version", async () => {
    secretManager.projects.secrets.create.mockResolvedValue({
      data: {
        name: "projects/test-project/secrets/my-secret",
        createTime: "2024-01-01T00:00:00Z",
      },
    });

    const client = await newClient();
    const metadata = await client.createSecret({ name: "my-secret" });

    expect(metadata).toEqual({
      ref: "projects/test-project/secrets/my-secret",
      name: "my-secret",
      createTime: new Date("2024-01-01T00:00:00Z"),
    });
    expect(secretManager.projects.secrets.create).toHaveBeenCalledWith({
      parent: "projects/test-project",
      secretId: "my-secret",
      requestBody: { replication: { automatic: {} } },
    });
    expect(secretManager.projects.secrets.addVersion).not.toHaveBeenCalled();
  });

  it("throws SecretAlreadyExistsError on a 409", async () => {
    secretManager.projects.secrets.create.mockRejectedValue({ status: 409 });

    const client = await newClient();
    await expect(client.createSecret({ name: "my-secret" })).rejects.toThrow(
      SecretAlreadyExistsError
    );
  });

  it("throws UnauthorizedError on a 403", async () => {
    secretManager.projects.secrets.create.mockRejectedValue({ status: 403 });

    const client = await newClient();
    await expect(client.createSecret({ name: "my-secret" })).rejects.toThrow(
      UnauthorizedError
    );
  });
});

describe("getSecret", () => {
  it("looks the secret up by a fully-qualified ref", async () => {
    const ref = "projects/test-project/secrets/my-secret" as SecretRef;
    secretManager.projects.secrets.get.mockResolvedValue({
      data: { name: ref, createTime: "2024-01-01T00:00:00Z" },
    });

    const client = await newClient();
    const metadata = await client.getSecret({ ref });

    expect(metadata).toEqual({
      ref,
      name: "my-secret",
      createTime: new Date("2024-01-01T00:00:00Z"),
    });
    expect(secretManager.projects.secrets.get).toHaveBeenCalledWith({
      name: ref,
    });
  });

  it("qualifies a bare secret id with the configured project", async () => {
    const qualified = "projects/test-project/secrets/my-secret";
    secretManager.projects.secrets.get.mockResolvedValue({
      data: { name: qualified, createTime: "2024-01-01T00:00:00Z" },
    });

    const client = await newClient();
    await client.getSecret({ ref: "my-secret" as SecretRef });

    // A bare id must be expanded to the fully-qualified resource name; passing
    // it through verbatim yields a 404 from GCP (the original identifyUser bug).
    expect(secretManager.projects.secrets.get).toHaveBeenCalledWith({
      name: qualified,
    });
  });

  it("throws SecretNotFoundError on a 404", async () => {
    secretManager.projects.secrets.get.mockRejectedValue({ status: 404 });

    const client = await newClient();
    await expect(
      client.getSecret({ ref: "my-secret" as SecretRef })
    ).rejects.toThrow(SecretNotFoundError);
  });
});

describe("deleteSecret", () => {
  it("deletes the secret by name", async () => {
    const ref = "projects/test-project/secrets/my-secret" as SecretRef;
    secretManager.projects.secrets.delete.mockResolvedValue({ data: {} });

    const client = await newClient();
    await client.deleteSecret({ ref });

    expect(secretManager.projects.secrets.delete).toHaveBeenCalledWith({
      name: ref,
    });
  });

  it("qualifies a bare secret id with the configured project", async () => {
    secretManager.projects.secrets.delete.mockResolvedValue({ data: {} });

    const client = await newClient();
    await client.deleteSecret({ ref: "my-secret" as SecretRef });

    expect(secretManager.projects.secrets.delete).toHaveBeenCalledWith({
      name: "projects/test-project/secrets/my-secret",
    });
  });

  it("throws SecretNotFoundError on a 404", async () => {
    secretManager.projects.secrets.delete.mockRejectedValue({ status: 404 });

    const client = await newClient();
    await expect(
      client.deleteSecret({
        ref: "projects/test-project/secrets/missing" as SecretRef,
      })
    ).rejects.toThrow(SecretNotFoundError);
  });

  it("throws UnauthorizedError on a 403", async () => {
    secretManager.projects.secrets.delete.mockRejectedValue({ status: 403 });

    const client = await newClient();
    await expect(
      client.deleteSecret({
        ref: "projects/test-project/secrets/my-secret" as SecretRef,
      })
    ).rejects.toThrow(UnauthorizedError);
  });
});

describe("getAllSecrets", () => {
  it("accumulates secrets across pages", async () => {
    secretManager.projects.secrets.list
      .mockResolvedValueOnce({
        data: {
          secrets: [
            {
              name: "projects/test-project/secrets/a",
              createTime: "2024-01-01T00:00:00Z",
            },
          ],
          nextPageToken: "page-2",
        },
      })
      .mockResolvedValueOnce({
        data: {
          secrets: [
            {
              name: "projects/test-project/secrets/b",
              createTime: "2024-01-02T00:00:00Z",
            },
          ],
          nextPageToken: null,
        },
      });

    const client = await newClient();
    const secrets = await client.getAllSecrets();

    expect(secrets.map((s) => s.name)).toEqual(["a", "b"]);
    expect(secretManager.projects.secrets.list).toHaveBeenNthCalledWith(1, {
      parent: "projects/test-project",
      pageToken: undefined,
    });
    expect(secretManager.projects.secrets.list).toHaveBeenNthCalledWith(2, {
      parent: "projects/test-project",
      pageToken: "page-2",
    });
  });
});

describe("getSecretVersions", () => {
  it("maps GCP version state strings onto SecretVersionState", async () => {
    const ref = "projects/test-project/secrets/my-secret" as SecretRef;
    secretManager.projects.secrets.versions.list.mockResolvedValue({
      data: {
        versions: [
          {
            name: `${ref}/versions/1`,
            state: "DISABLED",
            createTime: "2024-01-01T00:00:00Z",
          },
          {
            name: `${ref}/versions/2`,
            state: "ENABLED",
            createTime: "2024-01-02T00:00:00Z",
          },
        ],
        nextPageToken: null,
      },
    });

    const client = await newClient();
    const versions = await client.getSecretVersions({ ref });

    expect(versions).toEqual([
      {
        ref: `${ref}/versions/1`,
        secretRef: ref,
        state: "disabled",
        createTime: new Date("2024-01-01T00:00:00Z"),
      },
      {
        ref: `${ref}/versions/2`,
        secretRef: ref,
        state: "enabled",
        createTime: new Date("2024-01-02T00:00:00Z"),
      },
    ]);
  });

  it("throws SecretNotFoundError on a 404", async () => {
    secretManager.projects.secrets.versions.list.mockRejectedValue({
      status: 404,
    });

    const client = await newClient();
    await expect(
      client.getSecretVersions({
        ref: "projects/test-project/secrets/missing" as SecretRef,
      })
    ).rejects.toThrow(SecretNotFoundError);
  });

  it("throws on an unrecognized version state", async () => {
    const ref = "projects/test-project/secrets/my-secret" as SecretRef;
    secretManager.projects.secrets.versions.list.mockResolvedValue({
      data: {
        versions: [
          {
            name: `${ref}/versions/1`,
            state: "STATE_UNSPECIFIED",
            createTime: "2024-01-01T00:00:00Z",
          },
        ],
        nextPageToken: null,
      },
    });

    const client = await newClient();
    await expect(client.getSecretVersions({ ref })).rejects.toThrow(
      /Unrecognized GCP secret version state/
    );
  });
});

describe("getSecretValue", () => {
  const ref = "projects/test-project/secrets/my-secret" as SecretRef;
  const versionName = `${ref}/versions/latest`;
  const versionRef = `${ref}/versions/3`;

  it("decodes the base64 payload and returns the accessed version's metadata", async () => {
    secretManager.projects.secrets.versions.access.mockResolvedValue({
      data: {
        name: versionRef,
        payload: { data: Buffer.from("my-secret-value").toString("base64") },
      },
    });
    secretManager.projects.secrets.versions.get.mockResolvedValue({
      data: {
        name: versionRef,
        state: "ENABLED",
        createTime: "2024-01-03T00:00:00Z",
      },
    });

    const client = await newClient();
    const { value, version } = await client.getSecretValue({ ref });

    expect(value).toEqual(Buffer.from("my-secret-value"));
    expect(version).toEqual({
      ref: versionRef,
      secretRef: ref,
      state: "enabled",
      createTime: new Date("2024-01-03T00:00:00Z"),
    });
    expect(secretManager.projects.secrets.versions.access).toHaveBeenCalledWith(
      { name: versionName }
    );
    expect(secretManager.projects.secrets.versions.get).toHaveBeenCalledWith({
      name: versionRef,
    });
  });

  it("throws SecretNotFoundError on a 404", async () => {
    secretManager.projects.secrets.versions.access.mockRejectedValue({
      status: 404,
    });
    secretManager.projects.secrets.versions.get.mockResolvedValue({
      data: { name: versionRef, state: "ENABLED" },
    });

    const client = await newClient();
    await expect(client.getSecretValue({ ref })).rejects.toThrow(
      SecretNotFoundError
    );
  });

  it("throws UnauthorizedError on a 403", async () => {
    secretManager.projects.secrets.versions.access.mockRejectedValue({
      status: 403,
    });
    secretManager.projects.secrets.versions.get.mockResolvedValue({
      data: { name: versionRef, state: "ENABLED" },
    });

    const client = await newClient();
    await expect(client.getSecretValue({ ref })).rejects.toThrow(
      UnauthorizedError
    );
  });
});

describe("createSecretVersion", () => {
  const versionRef = "projects/test-project/secrets/my-secret/versions/1";

  it("adds a version with a 32-byte random base64 payload", async () => {
    secretManager.projects.secrets.addVersion.mockResolvedValue({
      data: { name: versionRef, state: "ENABLED" },
    });
    const ref = "projects/test-project/secrets/my-secret" as SecretRef;

    const client = await newClient();
    const metadata = await client.createSecretVersion({
      ref,
      type: "random",
      bytes: 32,
    });

    expect(metadata.ref).toBe(versionRef);
    expect(secretManager.projects.secrets.addVersion).toHaveBeenCalledTimes(1);
    const args = secretManager.projects.secrets.addVersion.mock.calls[0]?.[0];
    expect(args.parent).toBe(ref);
    expect(Buffer.from(args.requestBody.payload.data, "base64")).toHaveLength(
      32
    );
  });

  it("adds a version with an explicit value payload", async () => {
    secretManager.projects.secrets.addVersion.mockResolvedValue({
      data: { name: versionRef, state: "ENABLED" },
    });
    const ref = "projects/test-project/secrets/my-secret" as SecretRef;

    const client = await newClient();
    const value = Buffer.from("my-secret-value");
    const metadata = await client.createSecretVersion({
      ref,
      type: "value",
      value,
    });

    expect(metadata.ref).toBe(versionRef);
    expect(secretManager.projects.secrets.addVersion).toHaveBeenCalledTimes(1);
    const args = secretManager.projects.secrets.addVersion.mock.calls[0]?.[0];
    expect(args.parent).toBe(ref);
    expect(args.requestBody.payload.data).toBe(value.toString("base64"));
  });

  it("throws SecretNotFoundError on a 404", async () => {
    secretManager.projects.secrets.addVersion.mockRejectedValue({
      status: 404,
    });
    const client = await newClient();
    await expect(
      client.createSecretVersion({
        ref: "projects/test-project/secrets/missing" as SecretRef,
        type: "random",
        bytes: 32,
      })
    ).rejects.toThrow(SecretNotFoundError);
  });
});

describe("disableSecretVersion", () => {
  it("throws SecretVersionNotFoundError on a 404", async () => {
    secretManager.projects.secrets.versions.disable.mockRejectedValue({
      status: 404,
    });
    const client = await newClient();
    await expect(
      client.disableSecretVersion({
        ref: "projects/test-project/secrets/s/versions/1" as SecretVersionRef,
      })
    ).rejects.toThrow(SecretVersionNotFoundError);
  });
});

describe("deleteSecretVersion", () => {
  it("throws SecretVersionNotFoundError on a 404", async () => {
    secretManager.projects.secrets.versions.destroy.mockRejectedValue({
      status: 404,
    });
    const client = await newClient();
    await expect(
      client.deleteSecretVersion({
        ref: "projects/test-project/secrets/s/versions/1" as SecretVersionRef,
      })
    ).rejects.toThrow(SecretVersionNotFoundError);
  });
});
