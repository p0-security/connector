import { ConnectorError, createLogger } from "@p0security/connector-core";
import {
  SecretAlreadyExistsError,
  SecretNotFoundError,
  type SecretRef,
} from "@p0security/connector-secret-manager-client";
import type * as SecretManagerClientModule from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as folder from "../../../folder.ts";
import * as api from "../../../looker/looker-api.ts";
import * as roles from "../../../roles.ts";
import { t } from "../../../router.ts";
import { router } from "../handler.ts";

vi.mock("../../../looker/looker-api.ts");
vi.mock("../../../roles.ts");
vi.mock("../../../folder.ts");

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const secretManager = vi.hoisted(() => ({ create: vi.fn() }));

vi.mock(
  "@p0security/connector-secret-manager-client",
  async (importOriginal) => ({
    ...(await importOriginal<typeof SecretManagerClientModule>()),
    createSecretManagerClient: secretManager.create,
  })
);

const ADMIN_SECRET = "p0_install_looker_acme_admin-key";
const GRANT = "p0_access-token_looker_acme_1a2b3c4d";

const BASE_URL = "https://example.looker.app";
const ADMIN_KEY = { client_id: "admin-id", client_secret: "admin-secret" };
const SESSION = { baseUrl: BASE_URL, accessToken: "admin-token" };

const instance = {
  baseUrl: BASE_URL,
  secrets: {
    manager: "gcp" as const,
    adminKeySecretId: ADMIN_SECRET,
    projectId: "acme-prod",
  },
};

const context = { requestId: "r-1", ...instance };

/** What the fakes changed, in order. */
const events: string[] = [];

/** In-memory secrets: name → latest value, or `undefined` for a secret with
 * no version. */
const vault = new Map<string, string | undefined>();
const vaultFailures = { write: false, remove: false };

const fakeSecretManager = {
  getSecretValue: async ({ ref }: { ref: string }) => {
    const value = vault.get(ref);
    if (value === undefined) throw new SecretNotFoundError(ref as SecretRef);
    return { value };
  },
  createSecret: async ({ name }: { name: string }) => {
    if (vault.has(name)) throw new SecretAlreadyExistsError(name);
    vault.set(name, undefined);
    return { ref: name, name };
  },
  createSecretVersion: async ({
    ref,
    value,
  }: {
    ref: string;
    value: Buffer;
  }) => {
    if (vaultFailures.write) throw new Error("write failed");
    if (!vault.has(ref)) throw new SecretNotFoundError(ref as SecretRef);
    vault.set(ref, value.toString("utf8"));
  },
  deleteSecret: async ({ ref }: { ref: string }) => {
    if (vaultFailures.remove) throw new Error("delete failed");
    if (!vault.delete(ref)) throw new SecretNotFoundError(ref as SecretRef);
    events.push(`delete secret ${ref}`);
  },
};

type FakeAccount = { name: string; firstName?: string; lastName?: string };

/** The fake instance's Looker service accounts, by Looker user id. */
const accounts = new Map<string, FakeAccount>();
let nextAccountId = 100;

/** Each account's direct roles. */
const directRoles = new Map<string, string[]>();

/** Adds an account. A finished one has P0's first name, which the connector
 * sets once the account's key is stored. */
const addAccount = (name: string, finished = true) => {
  const id = String(nextAccountId++);
  accounts.set(id, finished ? { name, firstName: "P0" } : { name });
  return id;
};

/**
 * A silent logger whose child loggers are itself, so a test can read what any
 * of them logged.
 */
const newRecordingLogger = () => {
  const log = createLogger();
  log.level = "silent";
  vi.spyOn(log, "child").mockReturnValue(log);
  return { log, warn: vi.spyOn(log, "warn"), error: vi.spyOn(log, "error") };
};

let logs: ReturnType<typeof newRecordingLogger>;

const caller = () => router(t).createCaller({ logger: logs.log });

const provision = (userBody = GRANT) =>
  caller().provisionUser({ userBody, context });
const identify = () => caller().identifyUser({ userBody: GRANT, context });
const remove = (userId = GRANT) =>
  caller().deleteUser({ userId, userBody: userId, context });
type Policy = { model: string; level: "edit" | "read" } | null;
const setPolicies = (policies: Policy[]) =>
  caller().setPoliciesForUser({
    userId: GRANT,
    userBody: GRANT,
    policies,
    context,
  });

const connectorError = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    if (error instanceof ConnectorError) return error.data;
    throw error;
  }
  throw new Error("expected the call to throw");
};

beforeEach(() => {
  vi.resetAllMocks();
  logs = newRecordingLogger();
  events.length = 0;
  accounts.clear();
  directRoles.clear();
  nextAccountId = 100;
  vault.clear();
  vault.set(ADMIN_SECRET, JSON.stringify(ADMIN_KEY));
  vaultFailures.write = false;
  vaultFailures.remove = false;
  secretManager.create.mockResolvedValue(fakeSecretManager);

  vi.mocked(api.login).mockResolvedValue(SESSION);
  vi.mocked(api.logout).mockResolvedValue();
  vi.mocked(api.listServiceAccountIds).mockImplementation(async (_, name) =>
    [...accounts].filter(([, a]) => a.name === name).map(([id]) => id)
  );
  vi.mocked(api.listServiceAccounts).mockImplementation(async (_, name) =>
    [...accounts]
      .filter(([, a]) => a.name === name)
      .map(([id, a]) => ({ id, firstName: a.firstName }))
  );
  vi.mocked(api.createServiceAccount).mockImplementation(async (_, name) =>
    addAccount(name, false)
  );
  vi.mocked(api.setUserName).mockImplementation(async (_, id, name) => {
    Object.assign(accounts.get(id) ?? {}, name);
  });
  vi.mocked(api.createApiKey).mockImplementation(async (_, id) => ({
    client_id: `id${id}`,
    client_secret: `secret${id}`,
  }));
  vi.mocked(api.deleteServiceAccount).mockImplementation(async (_, id) => {
    if (accounts.delete(id)) events.push(`delete account ${id}`);
  });
  vi.mocked(api.setUserRoles).mockImplementation(async (_, id, roleIds) => {
    directRoles.set(id, roleIds);
    events.push(`set roles ${id} ${roleIds.join(",")}`);
  });
  vi.mocked(api.listDirectRoleIds).mockImplementation(async (_, id) => [
    ...(directRoles.get(id) ?? []),
  ]);
  vi.mocked(roles.setModelRole).mockImplementation(
    async (_, { model, level }) => `role-${model}-${level}`
  );
  vi.mocked(folder.setFolderAccess).mockImplementation(async (_, grant) => {
    events.push(`folder ${grant.userId} ${grant.access ?? "none"}`);
  });
});

describe("provisionUser", () => {
  it("creates a Looker service account named after the secret, and stores its key in the secret", async () => {
    await expect(provision()).resolves.toBe(GRANT);

    expect([...accounts]).toEqual([
      ["100", { name: GRANT, firstName: "P0", lastName: GRANT }],
    ]);
    expect(vault.get(GRANT)).toBe("id100:secret100");
  });

  it("signs in with the Admin key from the request's secret", async () => {
    await provision();

    expect(secretManager.create).toHaveBeenCalledWith({
      provider: "gcp",
      projectId: "acme-prod",
    });
    expect(api.login).toHaveBeenCalledWith(BASE_URL, ADMIN_KEY);
    expect(api.createServiceAccount).toHaveBeenCalledWith(SESSION, GRANT);
  });

  // The account is found by the user id, so a new and an existing account
  // must give the same one.
  it("gives the same user id for a new and an existing account", async () => {
    const created = await provision();
    const found = await provision();

    expect(found).toBe(created);
    expect(api.createServiceAccount).toHaveBeenCalledTimes(1);
    expect(api.createApiKey).toHaveBeenCalledTimes(1);
  });

  // An earlier attempt created the secret, failed to write it and deleted its
  // account.
  it("writes the key to a secret that an earlier attempt left empty", async () => {
    vault.set(GRANT, undefined);

    await provision();

    expect(vault.get(GRANT)).toBe("id100:secret100");
  });

  // The next attempt would find the account, and take it for one whose key is
  // in the secret.
  it.each([
    [
      "its key cannot be created",
      () => vi.mocked(api.createApiKey).mockRejectedValue(new Error("boom")),
    ],
    ["the secret cannot be written", () => (vaultFailures.write = true)],
    [
      "its key holds a line break",
      () =>
        vi.mocked(api.createApiKey).mockResolvedValue({
          client_id: "id100",
          client_secret: "secret\r\n100",
        }),
    ],
  ])("deletes the account it made when %s", async (_, fail) => {
    fail();

    await expect(provision()).rejects.toThrow();

    expect(api.deleteServiceAccount).toHaveBeenCalledWith(SESSION, "100");
    expect(accounts.size).toBe(0);
    expect(vault.get(GRANT)).toBeUndefined();
  });

  // The secret then holds the key of a deleted account, which no longer works.
  // The next attempt writes a new key over it.
  it("deletes the account it made when its names cannot be set", async () => {
    vi.mocked(api.setUserName).mockRejectedValueOnce(new Error("boom"));

    await expect(provision()).rejects.toThrow("boom");

    expect(accounts.size).toBe(0);
    expect(vault.has(GRANT)).toBe(false);
    await provision();
    expect(vault.get(GRANT)).toBe("id101:secret101");
  });

  // The secret holds the account's live key, and the account couldn't be
  // deleted.
  it("deletes the secret of a failed grant even when the account can't be deleted", async () => {
    vi.mocked(api.setUserName).mockRejectedValueOnce(new Error("boom"));
    vi.mocked(api.deleteServiceAccount).mockRejectedValueOnce(
      new Error("cannot delete")
    );

    await expect(provision()).rejects.toThrow("boom");

    expect(accounts.size).toBe(1);
    expect(vault.has(GRANT)).toBe(false);
  });

  it("fails with the grant's error when the secret can't be deleted either", async () => {
    vi.mocked(api.setUserName).mockImplementationOnce(async () => {
      vaultFailures.remove = true;
      throw new Error("boom");
    });

    await expect(provision()).rejects.toThrow("boom");

    // A vendor failure, not a bug in the connector.
    expect(logs.warn).toHaveBeenCalledWith(
      { error: expect.any(Error) },
      "failed to delete the secret of a failed grant, so it stays until the grant is retried or revoked"
    );
  });

  // The names mark a finished account, so they come after the key is stored.
  it("sets the account's names after storing its key", async () => {
    const order: string[] = [];
    vi.mocked(api.setUserName).mockImplementation(async (_, id, name) => {
      order.push(`names, secret ${vault.has(GRANT) ? "written" : "empty"}`);
      Object.assign(accounts.get(id) ?? {}, name);
    });

    await provision();

    expect(order).toEqual(["names, secret written"]);
  });

  // A failed grant can leave an account behind without a stored key: its
  // rollback failed, or Looker made it but the response was lost.
  it("deletes an unfinished account and provisions the grant again", async () => {
    addAccount(GRANT, false);

    await expect(provision()).resolves.toBe(GRANT);

    expect(events).toEqual(["delete account 100"]);
    expect([...accounts]).toEqual([
      ["101", { name: GRANT, firstName: "P0", lastName: GRANT }],
    ]);
    expect(vault.get(GRANT)).toBe("id101:secret101");
    expect(logs.warn).toHaveBeenCalledWith(
      { accountId: "100" },
      "deleted a Looker service account that a failed grant left behind"
    );
  });

  it("keeps a finished account", async () => {
    addAccount(GRANT);

    await provision();

    expect(api.deleteServiceAccount).not.toHaveBeenCalled();
    expect(api.createServiceAccount).not.toHaveBeenCalled();
  });

  // Another integration's grant secret is in the same project.
  it("refuses a P0 secret that isn't a Looker grant's", async () => {
    await expect(
      provision("p0_access-token_datadog_acme_1a2b")
    ).rejects.toThrow("is not namespaced");

    expect(api.login).not.toHaveBeenCalled();
  });

  it("fails with the first error when the account cannot be deleted either", async () => {
    vaultFailures.write = true;
    const deleteError = new Error("cannot delete");
    vi.mocked(api.deleteServiceAccount).mockRejectedValue(deleteError);

    const data = await connectorError(provision);

    expect(data.message).toBe(
      "The connector couldn't write the grant's secret p0_access-token_looker_acme_1a2b3c4d: write failed"
    );
    expect(logs.warn).toHaveBeenCalledWith(
      { accountId: "100", error: deleteError },
      "failed to delete the Looker service account of a failed grant, so it stays until someone deletes it"
    );
  });

  it("creates no secret when the account cannot be created", async () => {
    vi.mocked(api.createServiceAccount).mockRejectedValue(new Error("boom"));

    await expect(provision()).rejects.toThrow("boom");

    expect(api.deleteServiceAccount).not.toHaveBeenCalled();
    expect(vault.has(GRANT)).toBe(false);
  });

  // The Admin key can change any Looker service account.
  it("refuses a user that is not named like a P0 secret", async () => {
    addAccount("etl-bot");

    await expect(provision("etl-bot")).rejects.toThrow(
      'Username "etl-bot" is not namespaced'
    );

    expect(api.login).not.toHaveBeenCalled();
  });
});

describe("identifyUser", () => {
  it("is null when no Looker service account has the name", async () => {
    addAccount(`${GRANT}-other`);

    await expect(identify()).resolves.toBeNull();
    expect(api.listServiceAccounts).toHaveBeenCalledWith(SESSION, GRANT);
  });

  it("is the name when one does", async () => {
    addAccount(GRANT);

    await expect(identify()).resolves.toBe(GRANT);
  });

  // The framework skips deleteUser for a user it can't find, so a revoke
  // would otherwise leave the secret behind.
  it("deletes an unfinished account and its secret, and is null", async () => {
    addAccount(GRANT, false);
    vault.set(GRANT, "a dead key");

    await expect(identify()).resolves.toBeNull();

    expect(events).toEqual(["delete account 100", `delete secret ${GRANT}`]);
  });

  it("is null without a secret to delete", async () => {
    await expect(identify()).resolves.toBeNull();

    expect(events).toEqual([]);
  });

  // A revoke that deleted the account and then failed to delete the secret.
  // The framework finds no account on the retry, and skips deleteUser.
  it("deletes the secret of a revoke that deleted only the account", async () => {
    addAccount(GRANT);
    vault.set(GRANT, "a dead key");
    vaultFailures.remove = true;
    await expect(remove()).rejects.toThrow("delete failed");
    vaultFailures.remove = false;

    await expect(identify()).resolves.toBeNull();

    expect(events).toEqual(["delete account 100", `delete secret ${GRANT}`]);
    expect(vault.has(GRANT)).toBe(false);
  });

  it("keeps the secret of a finished account next to an unfinished one", async () => {
    addAccount(GRANT, false);
    addAccount(GRANT);
    vault.set(GRANT, "the key");

    await expect(identify()).resolves.toBe(GRANT);

    expect(events).toEqual(["delete account 100"]);
    expect(vault.get(GRANT)).toBe("the key");
  });
});

describe("deleteUser", () => {
  beforeEach(() => {
    addAccount(GRANT);
    vault.set(GRANT, "the key");
  });

  it("deletes the account, then the secret", async () => {
    await remove();

    expect(events).toEqual(["delete account 100", `delete secret ${GRANT}`]);
  });

  it("is idempotent", async () => {
    await remove();
    await expect(remove()).resolves.toBeNull();

    expect(api.deleteServiceAccount).toHaveBeenCalledTimes(1);
    expect(accounts.size).toBe(0);
    expect(vault.has(GRANT)).toBe(false);
  });

  // The control plane finds no account then, and does not call again.
  it("deletes the secret of an account that is already gone", async () => {
    accounts.clear();

    await remove();

    expect(api.deleteServiceAccount).not.toHaveBeenCalled();
    expect(events).toEqual([`delete secret ${GRANT}`]);
  });

  it("deletes the account when the secret is already gone", async () => {
    vault.delete(GRANT);

    await expect(remove()).resolves.toBeNull();

    expect(events).toEqual(["delete account 100"]);
  });

  // Nothing says that Looker keeps the names unique.
  it("deletes every account with the name", async () => {
    addAccount(GRANT);
    addAccount(`${GRANT}-other`);

    await remove();

    expect([...accounts.values()]).toEqual([
      { name: `${GRANT}-other`, firstName: "P0" },
    ]);
  });

  it("keeps the secret when the account cannot be deleted", async () => {
    vi.mocked(api.deleteServiceAccount).mockRejectedValue(new Error("boom"));

    await expect(remove()).rejects.toThrow("boom");

    expect(vault.get(GRANT)).toBe("the key");
  });

  it("fails when the secret cannot be deleted", async () => {
    vaultFailures.remove = true;

    await expect(remove()).rejects.toThrow("delete failed");

    expect(accounts.size).toBe(0);
  });

  it("refuses a user that is not named like a P0 secret", async () => {
    addAccount("etl-bot");

    await expect(remove("etl-bot")).rejects.toThrow(
      "Resource etl-bot is not namespaced"
    );

    expect(api.deleteServiceAccount).not.toHaveBeenCalled();
  });
});

describe("setPoliciesForUser", () => {
  const FOLDER = "42";
  const withFolder = { ...context, contentFolderId: FOLDER };
  const setPoliciesIn = (ctx: typeof context, policies: Policy[]) =>
    caller().setPoliciesForUser({
      userId: GRANT,
      userBody: GRANT,
      policies,
      context: ctx,
    });

  beforeEach(() => {
    addAccount(GRANT);
  });

  describe("for a model and a level", () => {
    it("gives the account P0's role for them, and only that", async () => {
      await expect(
        setPolicies([{ model: "thelook", level: "read" }])
      ).resolves.toBeNull();

      expect(roles.setModelRole).toHaveBeenCalledWith(SESSION, {
        model: "thelook",
        level: "read",
      });
      expect(directRoles.get("100")).toEqual(["role-thelook-read"]);
      expect(api.listDirectRoleIds).toHaveBeenCalledWith(SESSION, "100");
      expect(folder.setFolderAccess).not.toHaveBeenCalled();
    });

    it("replaces a role the account had", async () => {
      directRoles.set("100", ["role-old"]);

      await setPolicies([{ model: "thelook", level: "edit" }]);

      expect(directRoles.get("100")).toEqual(["role-thelook-edit"]);
    });

    it.each([
      ["edit", "edit"],
      ["read", undefined],
    ] as const)(
      "sets the account's access on the agent content folder for %s, before its role",
      async (level, access) => {
        await setPoliciesIn(withFolder, [{ model: "thelook", level }]);

        expect(folder.setFolderAccess).toHaveBeenCalledWith(SESSION, {
          folderId: FOLDER,
          userId: "100",
          access,
        });
        expect(events).toEqual([
          `folder 100 ${access ?? "none"}`,
          `set roles 100 role-thelook-${level}`,
        ]);
      }
    );

    // The account would otherwise hold its role until the revoke.
    it("gives no role when the agent content folder is gone", async () => {
      vi.mocked(folder.setFolderAccess).mockRejectedValue(
        new ConnectorError({
          type: "object_not_found",
          message: "no folder",
          payload: {},
        })
      );

      const data = await connectorError(() =>
        setPoliciesIn(withFolder, [{ model: "thelook", level: "edit" }])
      );

      expect(data.type).toBe("object_not_found");
      expect(roles.setModelRole).not.toHaveBeenCalled();
      expect(api.setUserRoles).not.toHaveBeenCalled();
    });

    // The read-back is what proves the grant.
    it("removes the roles and fails when Looker reports others than the one set", async () => {
      vi.mocked(api.listDirectRoleIds).mockResolvedValueOnce([
        "role-thelook-read",
        "role-admin",
      ]);

      const data = await connectorError(() =>
        setPoliciesIn(withFolder, [{ model: "thelook", level: "read" }])
      );

      expect(data).toEqual({
        type: "unknown",
        message: `Looker gave the Looker service account ${GRANT} other roles than the one P0 set, so P0 removed them`,
        payload: { requestId: "r-1", nRoles: 2 },
      });
      expect(directRoles.get("100")).toEqual([]);
    });

    it.each([[[]], [["role-other"]]])(
      "fails when Looker reports the roles %j",
      async (held) => {
        vi.mocked(api.listDirectRoleIds).mockResolvedValueOnce(held);

        await expect(
          setPolicies([{ model: "thelook", level: "read" }])
        ).rejects.toThrow("other roles than the one P0 set");
      }
    );

    it("fails with the read-back's error when the roles cannot be removed either", async () => {
      vi.mocked(api.listDirectRoleIds).mockResolvedValueOnce(["role-admin"]);
      const clearError = new Error("cannot clear");
      vi.mocked(api.setUserRoles)
        .mockResolvedValueOnce()
        .mockRejectedValueOnce(clearError);

      await expect(
        setPolicies([{ model: "thelook", level: "read" }])
      ).rejects.toThrow("other roles than the one P0 set");

      expect(logs.warn).toHaveBeenCalledWith(
        { accountId: "100", error: clearError },
        "failed to clear the roles of a Looker service account whose roles were not the ones set"
      );
    });

    it("sets no role when P0's role cannot be made", async () => {
      vi.mocked(roles.setModelRole).mockRejectedValue(new Error("edited"));

      await expect(
        setPoliciesIn(withFolder, [{ model: "thelook", level: "edit" }])
      ).rejects.toThrow("edited");

      expect(api.setUserRoles).not.toHaveBeenCalled();
    });

    it("fails when the account doesn't exist", async () => {
      accounts.clear();

      const data = await connectorError(() =>
        setPolicies([{ model: "thelook", level: "read" }])
      );

      expect(data).toEqual({
        type: "object_not_found",
        message: `Expected 1 Looker service account named ${GRANT}, found 0`,
        payload: { requestId: "r-1", nAccounts: 0 },
      });
      expect(roles.setModelRole).not.toHaveBeenCalled();
    });

    // The grant's key belongs to one of them only.
    it("fails, and gives no account a role, when two have the name", async () => {
      addAccount(GRANT);

      const data = await connectorError(() =>
        setPolicies([{ model: "thelook", level: "read" }])
      );

      expect(data.type).toBe("unknown");
      expect(data.message).toBe(
        `Expected 1 Looker service account named ${GRANT}, found 2`
      );
      expect(api.setUserRoles).not.toHaveBeenCalled();
    });
  });

  describe("for no access", () => {
    it("clears the account's roles", async () => {
      directRoles.set("100", ["role-thelook-read"]);

      await expect(setPolicies([null])).resolves.toBeNull();

      expect(directRoles.get("100")).toEqual([]);
      expect(roles.setModelRole).not.toHaveBeenCalled();
      expect(folder.setFolderAccess).not.toHaveBeenCalled();
    });

    it("takes away the account's access on the agent content folder", async () => {
      await setPoliciesIn(withFolder, [null]);

      expect(events).toEqual(["set roles 100 ", "folder 100 none"]);
    });

    it("clears every account with the name", async () => {
      addAccount(GRANT);

      await setPolicies([null]);

      expect(events).toEqual(["set roles 100 ", "set roles 101 "]);
    });

    it("does nothing when the account is gone", async () => {
      accounts.clear();

      await expect(setPolicies([null])).resolves.toBeNull();

      expect(api.setUserRoles).not.toHaveBeenCalled();
    });
  });

  it.each<[string, Policy[]]>([
    ["no policy", []],
    ["two policies", [null, { model: "thelook", level: "read" }]],
  ])("refuses %s", async (_, policies) => {
    const data = await connectorError(() => setPolicies(policies));

    expect(data.type).toBe("unknown");
    expect(data.message).toBe(
      "Invalid parameters for a Looker service account, expected exactly 1 policy"
    );
    expect(data.payload).toEqual({
      requestId: "r-1",
      nPolicies: policies.length,
    });
    // A control-plane bug, so an error and not a warning.
    expect(logs.error).toHaveBeenCalledWith(
      { nPolicies: policies.length },
      "expected exactly 1 policy for a Looker service account"
    );
    expect(api.login).not.toHaveBeenCalled();
  });
});

describe("list", () => {
  const listModels = () =>
    caller().list({ query: { type: "model", context: instance } });

  it("lists the instance's models, by name, with their labels", async () => {
    vi.mocked(api.listModels).mockResolvedValue([
      { name: "thelook", label: "The Look" },
      { name: "orders", label: "orders" },
    ]);

    await expect(listModels()).resolves.toEqual([
      { key: "thelook", value: "The Look" },
      { key: "orders", value: "orders" },
    ]);
    expect(api.login).toHaveBeenCalledWith(BASE_URL, ADMIN_KEY);
    expect(api.listModels).toHaveBeenCalledWith(SESSION);
    expect(api.logout).toHaveBeenCalledWith(SESSION);
  });

  it("is empty for an instance with no models", async () => {
    vi.mocked(api.listModels).mockResolvedValue([]);

    await expect(listModels()).resolves.toEqual([]);
  });
});

describe("the Looker session", () => {
  it("is signed out after the call", async () => {
    await provision();

    expect(api.logout).toHaveBeenCalledTimes(2);
    expect(api.logout).toHaveBeenCalledWith(SESSION);
  });

  it("is signed out when the call fails", async () => {
    vi.mocked(api.listServiceAccounts).mockRejectedValue(new Error("boom"));

    await expect(identify()).rejects.toThrow("boom");

    expect(api.logout).toHaveBeenCalledWith(SESSION);
  });

  // The token expires within the hour either way.
  it("does not fail the call when the sign-out fails", async () => {
    const error = new Error("cannot sign out");
    vi.mocked(api.logout).mockRejectedValue(error);

    await expect(provision()).resolves.toBe(GRANT);

    expect(logs.warn).toHaveBeenCalledWith(
      { error },
      "failed to sign out of Looker, so the token stays valid until it expires"
    );
  });

  it("is not opened when the Admin key cannot be read", async () => {
    vault.delete(ADMIN_SECRET);

    const data = await connectorError(identify);

    expect(data.type).toBe("object_not_found");
    expect(api.login).not.toHaveBeenCalled();
  });

  it("is not opened when the secret manager cannot be reached", async () => {
    const error = new Error("no such provider");
    secretManager.create.mockRejectedValue(error);

    const data = await connectorError(identify);

    expect(data).toEqual({
      type: "validation_error",
      message: "Invalid secret manager",
      payload: { manager: "gcp" },
    });
    expect(api.login).not.toHaveBeenCalled();
    expect(logs.warn).toHaveBeenCalledWith(
      { manager: "gcp", error },
      "failed to create the secret manager client"
    );
  });
});
