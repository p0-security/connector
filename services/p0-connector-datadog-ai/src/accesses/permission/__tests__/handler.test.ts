import { createLogger } from "@p0security/connector";
import type * as SecretManagerClientModule from "@p0security/secret-manager-client";
import type {
  SecretRef,
  SecretVersionRef,
} from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../../../datadog/datadog-api.ts";
import { t } from "../../../router.ts";
import { router } from "../handler.ts";

vi.mock("../../../datadog/datadog-api.ts");

const ADMIN_REF = "admin-keys";
const GRANT_REF = "grant-secret";

/** In-memory secrets: ref → latest value. */
const store = new Map<string, string>();
const writes = { fail: false };
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
        if (writes.fail) throw new Error("write failed");
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

const context = {
  requestId: "r-2",
  site: "datadoghq.com" as const,
  serviceAccountId: "sa-1",
  secrets: {
    manager: "gcp" as const,
    adminKeysSecretId: ADMIN_REF,
    projectId: "p",
  },
};

const TOKEN_NAME = `P0 ${GRANT_REF}`;

const caller = () => router(t).createCaller({ logger: createLogger() });

const setPolicies = (scopes: string[]) =>
  caller().setPoliciesForUser({
    userId: GRANT_REF,
    userBody: "p0_grant",
    policies: [{ scopes }],
    context,
  });

beforeEach(() => {
  vi.resetAllMocks();
  store.clear();
  secrets.clear();
  writes.fail = false;
  store.set(ADMIN_REF, JSON.stringify({ apiKey: "a", appKey: "b" }));
  vi.mocked(api.findServiceAccessTokenId).mockResolvedValue(undefined);
  vi.mocked(api.createServiceAccessToken).mockResolvedValue({
    id: "tok-2",
    key: "new-token",
  });
});

describe("setPoliciesForUser", () => {
  it("creates a token named after the secret and stores only the token", async () => {
    await setPolicies(["logs_read_data"]);

    expect(api.createServiceAccessToken).toHaveBeenCalledWith(
      { site: "datadoghq.com", apiKey: "a", appKey: "b" },
      { serviceAccountId: "sa-1", name: TOKEN_NAME, scopes: ["logs_read_data"] }
    );
    expect(store.get(GRANT_REF)).toBe("new-token");
  });

  it("changes the scopes of the existing token in place", async () => {
    vi.mocked(api.findServiceAccessTokenId).mockResolvedValue("tok-1");

    await setPolicies(["logs_read_data", "metrics_read"]);

    expect(api.findServiceAccessTokenId).toHaveBeenCalledWith(
      expect.anything(),
      { serviceAccountId: "sa-1", name: TOKEN_NAME }
    );
    expect(api.updateServiceAccessTokenScopes).toHaveBeenCalledWith(
      expect.anything(),
      {
        serviceAccountId: "sa-1",
        tokenId: "tok-1",
        scopes: ["logs_read_data", "metrics_read"],
      }
    );
    expect(api.createServiceAccessToken).not.toHaveBeenCalled();
    expect(api.revokeServiceAccessToken).not.toHaveBeenCalled();
  });

  it("revokes the token when no scopes remain", async () => {
    vi.mocked(api.findServiceAccessTokenId).mockResolvedValue("tok-1");

    await setPolicies([]);

    expect(api.revokeServiceAccessToken).toHaveBeenCalledWith(
      expect.anything(),
      { serviceAccountId: "sa-1", tokenId: "tok-1" }
    );
    expect(api.updateServiceAccessTokenScopes).not.toHaveBeenCalled();
    expect(api.createServiceAccessToken).not.toHaveBeenCalled();
  });

  it("creates nothing when no scopes remain and there is no token", async () => {
    await setPolicies([]);

    expect(api.createServiceAccessToken).not.toHaveBeenCalled();
    expect(api.revokeServiceAccessToken).not.toHaveBeenCalled();
  });

  it("revokes the token it made when the secret cannot be written", async () => {
    writes.fail = true;

    await expect(setPolicies(["logs_read_data"])).rejects.toThrow();

    expect(api.revokeServiceAccessToken).toHaveBeenCalledWith(
      expect.anything(),
      { serviceAccountId: "sa-1", tokenId: "tok-2" }
    );
  });

  it("fails when the scopes cannot be changed", async () => {
    store.set(GRANT_REF, "old-token");
    vi.mocked(api.findServiceAccessTokenId).mockResolvedValue("tok-1");
    vi.mocked(api.updateServiceAccessTokenScopes).mockRejectedValue(
      new Error("forbidden")
    );

    await expect(setPolicies(["logs_read_data"])).rejects.toThrow();
  });
});

describe("provisionUser", () => {
  // The token is named after the user id, so a new and an existing secret
  // must give the same id.
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
  it("revokes the token, then deletes the secret", async () => {
    store.set(GRANT_REF, "old-token");
    vi.mocked(api.findServiceAccessTokenId).mockResolvedValue("tok-1");

    await caller().deleteUser({
      userId: GRANT_REF,
      userBody: "p0_grant",
      context,
    });

    expect(api.revokeServiceAccessToken).toHaveBeenCalledWith(
      expect.anything(),
      { serviceAccountId: "sa-1", tokenId: "tok-1" }
    );
    expect(store.has(GRANT_REF)).toBe(false);
  });

  it("keeps the secret when the token cannot be revoked", async () => {
    store.set(GRANT_REF, "old-token");
    vi.mocked(api.findServiceAccessTokenId).mockResolvedValue("tok-1");
    vi.mocked(api.revokeServiceAccessToken).mockRejectedValue(
      new Error("forbidden")
    );

    await expect(
      caller().deleteUser({ userId: GRANT_REF, userBody: "p0_grant", context })
    ).rejects.toThrow();
    expect(store.get(GRANT_REF)).toBe("old-token");
  });

  it("deletes a secret that has no token", async () => {
    await caller().deleteUser({
      userId: GRANT_REF,
      userBody: "p0_grant",
      context,
    });

    expect(api.revokeServiceAccessToken).not.toHaveBeenCalled();
    expect(store.has(GRANT_REF)).toBe(false);
  });
});

describe("list", () => {
  it("lists the service account's permissions as scopes", async () => {
    vi.mocked(api.listUserPermissions).mockResolvedValue([
      { name: "logs_read_data", displayName: "Logs Read Data" },
    ]);

    await expect(
      caller().list({ query: { type: "scope", context } })
    ).resolves.toEqual([{ key: "logs_read_data", value: "logs_read_data" }]);
    expect(api.listUserPermissions).toHaveBeenCalledWith(
      expect.anything(),
      "sa-1"
    );
  });
});
