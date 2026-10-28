import { createLogger } from "@p0security/connector";
import type * as SecretManagerClientModule from "@p0security/secret-manager-client";
import type {
  SecretRef,
  SecretVersionRef,
} from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../../../atlas/atlas-api.ts";
import type { McpConfig, McpConfigSecret } from "../../../atlas/atlas-api.ts";
import { t } from "../../../router.ts";
import { router } from "../handler.ts";

vi.mock("../../../atlas/atlas-api.ts");

const CLIENT_SECRET_REF = "client-secret";
const GRANT_REF = "grant-secret";
const PROJECT = "0123456789abcdef01234567";

/** In-memory secrets: ref → latest value. */
const store = new Map<string, string>();
const secrets = new Set<string>();

vi.mock("@p0security/secret-manager-client", async (importOriginal) => {
  const actual = await importOriginal<typeof SecretManagerClientModule>();
  return {
    ...actual,
    createSecretManagerClient: async () => ({
      getSecretValue: async ({ ref }: { ref: string }) => {
        const value = store.get(ref);
        if (value === undefined)
          throw new actual.SecretVersionNotFoundError(ref as SecretVersionRef);
        return { value };
      },
      createSecretVersion: async ({
        ref,
        value,
      }: {
        ref: string;
        value: Buffer;
      }) => {
        store.set(ref, value.toString("utf8"));
      },
      deleteSecret: async ({ ref }: { ref: string }) => {
        store.delete(ref);
      },
      // Like GCP: a ref is the full resource name, a name is its last part.
      createSecret: async ({ name }: { name: string }) => {
        secrets.add(name);
        return { ref: `projects/1/secrets/${name}`, name };
      },
      getSecret: async ({ ref }: { ref: string }) => {
        const name = ref.split("/").pop() ?? ref;
        if (!secrets.has(name))
          throw new actual.SecretNotFoundError(ref as SecretRef);
        return { ref: `projects/1/secrets/${name}`, name };
      },
    }),
  };
});

/** An in-memory Atlas project: its MCP configurations and their secrets. */
let configs: McpConfig[];
let configSecrets: Map<string, McpConfigSecret[]>;
let nextSecret: number;

const atlas = {
  findMcpConfig: vi.fn(async (name: string) =>
    configs.find(({ mcpConfigName }) => mcpConfigName === name)
  ),
  createMcpConfig: vi.fn(async (name: string, roles: string[]) => {
    const config = {
      mcpConfigId: `config-${configs.length}`,
      mcpConfigName: name,
      clientId: `mdb_sa_id_${configs.length}`,
      roles,
    };
    configs.push(config);
    return config;
  }),
  setMcpConfigRoles: vi.fn(async (id: string, roles: string[]) => {
    configs.find(({ mcpConfigId }) => mcpConfigId === id)!.roles = roles;
    return undefined;
  }),
  deleteMcpConfig: vi.fn(async (id: string) => {
    configs = configs.filter(({ mcpConfigId }) => mcpConfigId !== id);
    configSecrets.delete(id);
    return undefined;
  }),
  listMcpConfigSecrets: vi.fn(async (id: string) => [
    ...(configSecrets.get(id) ?? []),
  ]),
  createMcpConfigSecret: vi.fn(async (id: string) => {
    const existing = configSecrets.get(id) ?? [];
    if (existing.length >= 2) throw new Error("secret limit (2) reached");
    const secret = {
      id: `s${nextSecret}`,
      createdAt: `2026-10-26T00:00:0${nextSecret}Z`,
    };
    nextSecret++;
    configSecrets.set(id, [...existing, secret]);
    return { ...secret, secret: `value-${secret.id}` };
  }),
  deleteMcpConfigSecret: vi.fn(async (id: string, secretId: string) => {
    configSecrets.set(
      id,
      (configSecrets.get(id) ?? []).filter((s) => s.id !== secretId)
    );
    return undefined;
  }),
};

const context = {
  requestId: "r-2",
  atlasProjectId: PROJECT,
  clientId: "mdb_sa_id_admin",
  secrets: {
    manager: "gcp" as const,
    clientSecretSecretId: CLIENT_SECRET_REF,
    projectId: "p",
  },
};

const caller = () => router(t).createCaller({ logger: createLogger() });

const setPolicies = (roles: string[]) =>
  caller().setPoliciesForUser({
    userId: GRANT_REF,
    userBody: "p0_grant",
    policies: [{ roles: roles as any }],
    context,
  });

beforeEach(() => {
  vi.clearAllMocks();
  store.clear();
  secrets.clear();
  configs = [];
  configSecrets = new Map();
  nextSecret = 1;
  store.set(CLIENT_SECRET_REF, "admin-s3cret");
  vi.mocked(api.newAtlasClient).mockReturnValue(atlas);
  vi.mocked(api.requestToken).mockImplementation(
    async ({ clientId, clientSecret }) => `token:${clientId}:${clientSecret}`
  );
});

describe("setPoliciesForUser", () => {
  it("creates a configuration with the roles and stores its token", async () => {
    await setPolicies(["GROUP_DATA_ACCESS_READ_ONLY"]);

    expect(api.requestToken).toHaveBeenCalledWith(
      { clientId: "mdb_sa_id_admin", clientSecret: "admin-s3cret" },
      "admin token request"
    );
    expect(api.newAtlasClient).toHaveBeenCalledWith(
      "token:mdb_sa_id_admin:admin-s3cret",
      PROJECT
    );
    expect(configs).toEqual([
      expect.objectContaining({
        mcpConfigName: expect.stringMatching(/^p0-[0-9a-f]{32}$/),
        roles: ["GROUP_DATA_ACCESS_READ_ONLY"],
      }),
    ]);
    expect(store.get(GRANT_REF)).toBe("token:mdb_sa_id_0:value-s1");
    expect(configSecrets.get("config-0")).toEqual([
      expect.objectContaining({ id: "s1" }),
    ]);
  });

  it("changes the roles of the grant's configuration", async () => {
    await setPolicies(["GROUP_DATA_ACCESS_READ_ONLY"]);
    await setPolicies(["GROUP_DATA_ACCESS_READ_WRITE", "GROUP_READ_ONLY"]);

    expect(configs).toHaveLength(1);
    expect(configs[0].roles).toEqual([
      "GROUP_DATA_ACCESS_READ_WRITE",
      "GROUP_READ_ONLY",
    ]);
  });

  it("leaves unchanged roles alone", async () => {
    await setPolicies(["GROUP_READ_ONLY", "GROUP_DATA_ACCESS_READ_ONLY"]);
    await setPolicies(["GROUP_DATA_ACCESS_READ_ONLY", "GROUP_READ_ONLY"]);

    expect(atlas.setMcpConfigRoles).not.toHaveBeenCalled();
  });

  it("replaces the token and deletes the old secret only after storing it", async () => {
    await setPolicies(["GROUP_DATA_ACCESS_READ_ONLY"]);
    atlas.deleteMcpConfigSecret.mockImplementationOnce(async (id, secretId) => {
      // The new token is already in place when the old secret goes.
      expect(store.get(GRANT_REF)).toBe("token:mdb_sa_id_0:value-s2");
      configSecrets.set(
        id,
        (configSecrets.get(id) ?? []).filter((s) => s.id !== secretId)
      );
      return undefined;
    });

    await setPolicies(["GROUP_DATA_ACCESS_READ_ONLY"]);

    expect(atlas.deleteMcpConfigSecret).toHaveBeenCalledWith("config-0", "s1");
    expect(configSecrets.get("config-0")).toEqual([
      expect.objectContaining({ id: "s2" }),
    ]);
  });

  it("makes room when an earlier rotation left 2 secrets", async () => {
    await setPolicies(["GROUP_DATA_ACCESS_READ_ONLY"]);
    await atlas.createMcpConfigSecret("config-0");

    await setPolicies(["GROUP_DATA_ACCESS_READ_ONLY"]);

    expect(store.get(GRANT_REF)).toBe("token:mdb_sa_id_0:value-s3");
    expect(configSecrets.get("config-0")).toEqual([
      expect.objectContaining({ id: "s3" }),
    ]);
  });

  it("keeps the old token when Atlas refuses the new one", async () => {
    await setPolicies(["GROUP_DATA_ACCESS_READ_ONLY"]);
    vi.mocked(api.requestToken).mockImplementation(async ({ clientId }) => {
      if (clientId === "mdb_sa_id_0") throw new Error("invalid_client");
      return "admin";
    });

    await expect(
      setPolicies(["GROUP_DATA_ACCESS_READ_ONLY"])
    ).rejects.toThrow();
    expect(store.get(GRANT_REF)).toBe("token:mdb_sa_id_0:value-s1");
  });

  it("does nothing in Atlas when no roles remain", async () => {
    await setPolicies([]);

    expect(api.newAtlasClient).not.toHaveBeenCalled();
  });

  it("rejects a role that MCP configurations do not accept", async () => {
    await expect(setPolicies(["GROUP_CHARTS_ADMIN"])).rejects.toThrow();
    expect(api.newAtlasClient).not.toHaveBeenCalled();
  });

  it("fails when the client secret is empty", async () => {
    store.set(CLIENT_SECRET_REF, "");

    await expect(setPolicies(["GROUP_READ_ONLY"])).rejects.toThrow(
      "The Atlas service account client secret is empty"
    );
    expect(api.requestToken).not.toHaveBeenCalled();
  });
});

describe("provisionUser", () => {
  it("gives the same user id for a new and an existing secret", async () => {
    const provision = () =>
      caller().provisionUser({ userBody: "p0_grant", context });

    const created = await provision();
    const found = await provision();

    expect(created).toBe("projects/1/secrets/p0_grant");
    expect(found).toBe(created);
  });
});

describe("deleteUser", () => {
  const deleteUser = () =>
    caller().deleteUser({ userId: GRANT_REF, userBody: "p0_grant", context });

  it("deletes the configuration, then the secret", async () => {
    await setPolicies(["GROUP_READ_ONLY"]);

    await deleteUser();

    expect(atlas.deleteMcpConfig).toHaveBeenCalledWith("config-0");
    expect(configs).toEqual([]);
    expect(store.has(GRANT_REF)).toBe(false);
  });

  it("keeps the secret when the configuration delete fails", async () => {
    await setPolicies(["GROUP_READ_ONLY"]);
    atlas.deleteMcpConfig.mockRejectedValueOnce(new Error("unavailable"));

    await expect(deleteUser()).rejects.toThrow("unavailable");
    expect(store.has(GRANT_REF)).toBe(true);
  });

  it("deletes the secret when no configuration was made", async () => {
    store.set(GRANT_REF, "");

    await deleteUser();

    expect(atlas.deleteMcpConfig).not.toHaveBeenCalled();
    expect(store.has(GRANT_REF)).toBe(false);
  });
});

describe("list", () => {
  it("lists the project roles with their Atlas labels", async () => {
    const roles = await caller().list({ query: { type: "role", context } });

    expect(roles).toContainEqual({
      key: "GROUP_DATA_ACCESS_READ_ONLY",
      value: "Project Data Access Read Only",
    });
    expect(roles).toHaveLength(11);
  });
});

describe("request context", () => {
  it.each(["", "0123", "0123456789ABCDEF01234567"])(
    "rejects the Atlas project id %j",
    async (atlasProjectId) => {
      await expect(
        caller().setPoliciesForUser({
          userId: GRANT_REF,
          userBody: "p0_grant",
          policies: [{ roles: ["GROUP_READ_ONLY"] }],
          context: { ...context, atlasProjectId },
        })
      ).rejects.toThrow();
      expect(api.requestToken).not.toHaveBeenCalled();
    }
  );
});
