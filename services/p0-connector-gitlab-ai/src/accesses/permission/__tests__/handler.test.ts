import { createLogger } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/connector-secret-manager-client";
import type {
  SecretRef,
  SecretVersionRef,
} from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../../../gitlab/gitlab-api.ts";
import { t } from "../../../router.ts";
import { router } from "../handler.ts";

vi.mock("../../../gitlab/gitlab-api.ts");

const ADMIN_REF = "admin-token";
const GRANT_REF = "grant-secret";

/** In-memory secrets: ref → latest value. */
const store = new Map<string, string>();
const writes = { fail: false };
const secrets = new Set<string>();

vi.mock(
  "@p0security/connector-secret-manager-client",
  async (importOriginal) => {
    const actual = await importOriginal<typeof SecretManagerClientModule>();
    return {
      ...actual,
      createSecretManagerClient: async () => ({
        getSecretValue: async ({ ref }: { ref: string }) => {
          const value = store.get(ref);
          if (value === undefined)
            throw new actual.SecretVersionNotFoundError(
              ref as SecretVersionRef
            );
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
  }
);

const context = {
  requestId: "r-2",
  groupId: "42",
  secrets: {
    manager: "gcp" as const,
    adminTokenSecretId: ADMIN_REF,
    projectId: "p",
  },
};

const AUTH = { token: "admin" };
const TOKEN_NAME = `P0 ${GRANT_REF}`;
const SA_ID = 9;

const caller = () => router(t).createCaller({ logger: createLogger() });

const setPolicies = (
  memberships: { project: string; role: "developer" | "reporter" }[]
) =>
  caller().setPoliciesForUser({
    userId: GRANT_REF,
    userBody: "p0_grant",
    policies: [{ memberships }],
    context,
  });

const projects: Record<string, number> = { "g/a": 1, "g/b": 2 };

beforeEach(() => {
  vi.resetAllMocks();
  store.clear();
  secrets.clear();
  writes.fail = false;
  store.set(ADMIN_REF, "admin\n");
  vi.mocked(api.findServiceAccountId).mockResolvedValue(undefined);
  vi.mocked(api.createServiceAccount).mockResolvedValue(SA_ID);
  vi.mocked(api.findServiceAccountTokenId).mockResolvedValue(undefined);
  vi.mocked(api.getProject).mockImplementation(async (_, path) => ({
    id: projects[path],
    pathWithNamespace: path,
  }));
  vi.mocked(api.createServiceAccountToken).mockImplementation(
    async (_, { name }) =>
      name === TOKEN_NAME
        ? { id: 70, token: "grant-token" }
        : { id: 71, token: "probe-token" }
  );
  vi.mocked(api.listMemberProjects).mockResolvedValue([]);
});

describe("setPoliciesForUser", () => {
  it("creates the service account, adds its memberships, then stores its token", async () => {
    await setPolicies([{ project: "g/a", role: "developer" }]);

    expect(api.createServiceAccount).toHaveBeenCalledWith(AUTH, {
      groupId: "42",
      username: expect.stringMatching(/^p0-grant-[0-9a-f]{32}$/),
      name: "P0 grant",
    });
    expect(api.setProjectMember).toHaveBeenCalledWith(AUTH, {
      projectId: 1,
      userId: SA_ID,
      accessLevel: 30,
    });
    expect(api.createServiceAccountToken).toHaveBeenCalledWith(AUTH, {
      groupId: "42",
      userId: SA_ID,
      name: TOKEN_NAME,
      scopes: ["mcp"],
    });
    // The MCP server keeps its first answer, so the membership comes first.
    expect(
      vi.mocked(api.setProjectMember).mock.invocationCallOrder[0]
    ).toBeLessThan(
      vi.mocked(api.createServiceAccountToken).mock.invocationCallOrder[0]
    );
    // A new service account has no memberships to look up.
    expect(api.listMemberProjects).not.toHaveBeenCalled();
    expect(store.get(GRANT_REF)).toBe("grant-token");
  });

  it("changes the memberships of an existing service account and keeps its token", async () => {
    vi.mocked(api.findServiceAccountId).mockResolvedValue(SA_ID);
    vi.mocked(api.findServiceAccountTokenId).mockResolvedValue(70);
    vi.mocked(api.listMemberProjects).mockResolvedValue([
      { id: 1, pathWithNamespace: "g/a" },
    ]);

    await setPolicies([{ project: "g/b", role: "reporter" }]);

    expect(api.createServiceAccount).not.toHaveBeenCalled();
    expect(api.setProjectMember).toHaveBeenCalledWith(AUTH, {
      projectId: 2,
      userId: SA_ID,
      accessLevel: 20,
    });
    expect(api.removeProjectMember).toHaveBeenCalledWith(AUTH, {
      projectId: 1,
      userId: SA_ID,
    });
    // The membership check uses the service account's own short-lived token,
    // and revokes it.
    expect(api.listMemberProjects).toHaveBeenCalledWith({
      token: "probe-token",
    });
    expect(api.revokeServiceAccountToken).toHaveBeenCalledWith(AUTH, {
      groupId: "42",
      userId: SA_ID,
      tokenId: 71,
    });
    expect(api.createServiceAccountToken).not.toHaveBeenCalledWith(
      AUTH,
      expect.objectContaining({ name: TOKEN_NAME })
    );
  });

  it("revokes the membership-check token when the check fails", async () => {
    vi.mocked(api.findServiceAccountId).mockResolvedValue(SA_ID);
    vi.mocked(api.listMemberProjects).mockRejectedValue(new Error("boom"));

    await expect(
      setPolicies([{ project: "g/a", role: "developer" }])
    ).rejects.toThrow();
    expect(api.revokeServiceAccountToken).toHaveBeenCalledWith(AUTH, {
      groupId: "42",
      userId: SA_ID,
      tokenId: 71,
    });
  });

  it("deletes the service account when no memberships remain", async () => {
    vi.mocked(api.findServiceAccountId).mockResolvedValue(SA_ID);

    await setPolicies([]);

    expect(api.deleteServiceAccount).toHaveBeenCalledWith(AUTH, {
      groupId: "42",
      userId: SA_ID,
    });
    expect(api.createServiceAccount).not.toHaveBeenCalled();
  });

  it("creates nothing when no memberships remain and there is no service account", async () => {
    await setPolicies([]);

    expect(api.createServiceAccount).not.toHaveBeenCalled();
    expect(api.deleteServiceAccount).not.toHaveBeenCalled();
  });

  it("revokes the token it made when the secret cannot be written", async () => {
    writes.fail = true;

    await expect(
      setPolicies([{ project: "g/a", role: "developer" }])
    ).rejects.toThrow();

    expect(api.revokeServiceAccountToken).toHaveBeenCalledWith(AUTH, {
      groupId: "42",
      userId: SA_ID,
      tokenId: 70,
    });
  });

  it("fails on more than one policy", async () => {
    await expect(
      caller().setPoliciesForUser({
        userId: GRANT_REF,
        userBody: "p0_grant",
        policies: [{ memberships: [] }, { memberships: [] }],
        context,
      })
    ).rejects.toThrow();
  });
});

describe("provisionUser", () => {
  // The service account and token are named after the user id, so a new and
  // an existing secret must give the same id.
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
  it("deletes the service account, then the secret", async () => {
    store.set(GRANT_REF, "grant-token");
    vi.mocked(api.findServiceAccountId).mockResolvedValue(SA_ID);

    await caller().deleteUser({
      userId: GRANT_REF,
      userBody: "p0_grant",
      context,
    });

    expect(api.deleteServiceAccount).toHaveBeenCalledWith(AUTH, {
      groupId: "42",
      userId: SA_ID,
    });
    expect(store.has(GRANT_REF)).toBe(false);
  });

  it("keeps the secret when the service account cannot be deleted", async () => {
    store.set(GRANT_REF, "grant-token");
    vi.mocked(api.findServiceAccountId).mockResolvedValue(SA_ID);
    vi.mocked(api.deleteServiceAccount).mockRejectedValue(
      new Error("forbidden")
    );

    await expect(
      caller().deleteUser({ userId: GRANT_REF, userBody: "p0_grant", context })
    ).rejects.toThrow();
    expect(store.get(GRANT_REF)).toBe("grant-token");
  });

  it("deletes a secret that has no service account", async () => {
    await caller().deleteUser({
      userId: GRANT_REF,
      userBody: "p0_grant",
      context,
    });

    expect(api.deleteServiceAccount).not.toHaveBeenCalled();
    expect(store.has(GRANT_REF)).toBe(false);
  });
});

describe("list", () => {
  it("lists every role of every project of the group", async () => {
    vi.mocked(api.listGroupProjects).mockResolvedValue([
      { id: 1, pathWithNamespace: "g/a" },
    ]);

    await expect(
      caller().list({ query: { type: "policy", context } })
    ).resolves.toEqual(
      ["guest", "reporter", "developer", "maintainer"].map((role) => ({
        key: `g/a:${role}`,
        value: `g/a:${role}`,
        group: "g/a",
      }))
    );
    expect(api.listGroupProjects).toHaveBeenCalledWith(AUTH, "42");
  });
});
