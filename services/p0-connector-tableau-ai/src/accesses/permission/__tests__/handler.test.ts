import { createLogger } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/connector-secret-manager-client";
import type {
  SecretRef,
  SecretVersionRef,
} from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { t } from "../../../router.ts";
import * as api from "../../../tableau/tableau-api.ts";
import { router } from "../handler.ts";

vi.mock("../../../tableau/tableau-api.ts");

const ADMIN_REF = "admin-app";
const GRANT_REF = "grant-secret";
const PROJECT_A = "project-a";
const PROJECT_B = "project-b";

/** In-memory secrets: ref → latest value. */
const store = new Map<string, string>();
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
  requestId: "r-1",
  server: "https://us-east-1.online.tableau.com",
  contentUrl: "p0dev",
  adminUser: "admin@example.com",
  agentMailbox: "agents@example.com",
  secrets: {
    manager: "gcp" as const,
    adminAppSecretId: ADMIN_REF,
    projectId: "p",
  },
};

const site = { server: context.server, contentUrl: context.contentUrl };
const admin = { site, siteId: "site-1", token: "admin-token" };
const agentSession = { site, siteId: "site-1", token: "agent-token" };
const agent = { id: "agent-1", name: "agent", siteRole: "Viewer" };

/** The agent user's project capabilities, by project id. */
const projectCapabilities = new Map<string, api.Capability[]>();

const caller = () => router(t).createCaller({ logger: createLogger() });

const setPolicies = (grants: string[]) =>
  caller().setPoliciesForUser({
    userId: GRANT_REF,
    userBody: "p0_grant",
    policies: [{ grants }],
    context,
  });

beforeEach(() => {
  vi.resetAllMocks();
  store.clear();
  secrets.clear();
  projectCapabilities.clear();
  store.set(
    ADMIN_REF,
    JSON.stringify({ clientId: "c", secretId: "s", secret: "x" })
  );
  vi.mocked(api.signIn).mockImplementation(async (_site, _app, user) =>
    user === context.adminUser ? admin : agentSession
  );
  vi.mocked(api.listLockedProjects).mockResolvedValue([
    { id: PROJECT_A, name: "A", contentPermissions: "LockedToProject" },
    { id: PROJECT_B, name: "B", contentPermissions: "LockedToProject" },
  ]);
  vi.mocked(api.findUser).mockResolvedValue(undefined);
  vi.mocked(api.createUser).mockResolvedValue(agent);
  vi.mocked(api.getUserCapabilities).mockImplementation(
    async (_session, projectId, target) =>
      target === "project" ? (projectCapabilities.get(projectId) ?? []) : []
  );
});

describe("setPoliciesForUser", () => {
  it("creates a plus-addressed agent user and stores its session token", async () => {
    await setPolicies([`read:${PROJECT_A}`]);

    expect(api.createUser).toHaveBeenCalledWith(
      admin,
      expect.stringMatching(/^agents\+p0-[0-9a-f]{16}@example\.com$/),
      "Viewer"
    );
    expect(store.get(GRANT_REF)).toBe("agent-token");
    expect(api.signOut).toHaveBeenCalledWith(admin);
  });

  it("names the same agent user for the same secret", async () => {
    await setPolicies([`read:${PROJECT_A}`]);
    await setPolicies([`read:${PROJECT_A}`]);

    const [[, first], [, second]] = vi.mocked(api.findUser).mock.calls;
    expect(second).toBe(first);
  });

  it("gives read access only to the requested project", async () => {
    await setPolicies([`read:${PROJECT_A}`]);

    const granted = vi
      .mocked(api.addUserCapabilities)
      .mock.calls.map(([, projectId, target]) => `${projectId}/${target}`);
    expect(granted).toEqual([
      `${PROJECT_A}/project`,
      `${PROJECT_A}/workbooks`,
      `${PROJECT_A}/datasources`,
    ]);
  });

  it("uses write when one request asks for read and another for write", async () => {
    await setPolicies([`read:${PROJECT_A}`, `write:${PROJECT_A}`]);

    expect(api.createUser).toHaveBeenCalledWith(
      admin,
      expect.any(String),
      "ExplorerCanPublish"
    );
    expect(api.addUserCapabilities).toHaveBeenCalledWith(
      admin,
      PROJECT_A,
      "project",
      agent.id,
      [
        { name: "Read", mode: "Allow" },
        { name: "Write", mode: "Allow" },
      ]
    );
  });

  it("removes access to a project that is no longer requested", async () => {
    vi.mocked(api.findUser).mockResolvedValue(agent);
    projectCapabilities.set(PROJECT_B, [{ name: "Read", mode: "Allow" }]);

    await setPolicies([`read:${PROJECT_A}`]);

    expect(api.removeUserCapability).toHaveBeenCalledWith(
      admin,
      PROJECT_B,
      "project",
      agent.id,
      { name: "Read", mode: "Allow" }
    );
    expect(api.createUser).not.toHaveBeenCalled();
  });

  it("leaves a project alone when its level is unchanged", async () => {
    vi.mocked(api.findUser).mockResolvedValue(agent);
    projectCapabilities.set(PROJECT_A, [{ name: "Read", mode: "Allow" }]);

    await setPolicies([`read:${PROJECT_A}`]);

    expect(api.addUserCapabilities).not.toHaveBeenCalled();
    expect(api.removeUserCapability).not.toHaveBeenCalled();
  });

  it("refuses a project that is not locked", async () => {
    await expect(setPolicies(["read:unlocked"])).rejects.toThrow(
      /locked to the project/
    );
    expect(store.has(GRANT_REF)).toBe(false);
  });

  it("removes the agent user when no grants remain", async () => {
    vi.mocked(api.findUser).mockResolvedValue(agent);

    await setPolicies([]);

    expect(api.removeUser).toHaveBeenCalledWith(admin, agent.id);
    expect(api.addUserCapabilities).not.toHaveBeenCalled();
    expect(store.has(GRANT_REF)).toBe(false);
  });
});

describe("provisionUser", () => {
  // The agent user's name is derived from the user id, so a new and an
  // existing secret must give the same id.
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
  it("removes the agent user, then deletes the secret", async () => {
    store.set(GRANT_REF, "old-token");
    vi.mocked(api.findUser).mockResolvedValue(agent);

    await caller().deleteUser({
      userId: GRANT_REF,
      userBody: "p0_grant",
      context,
    });

    expect(api.removeUser).toHaveBeenCalledWith(admin, agent.id);
    expect(store.has(GRANT_REF)).toBe(false);
  });

  it("keeps the secret when the agent user cannot be removed", async () => {
    store.set(GRANT_REF, "old-token");
    vi.mocked(api.findUser).mockResolvedValue(agent);
    vi.mocked(api.removeUser).mockRejectedValue(new Error("forbidden"));

    await expect(
      caller().deleteUser({ userId: GRANT_REF, userBody: "p0_grant", context })
    ).rejects.toThrow();
    expect(store.get(GRANT_REF)).toBe("old-token");
  });
});

describe("list", () => {
  it("offers read and write for each locked project", async () => {
    const items = await caller().list({ query: { type: "project", context } });

    expect(items).toEqual([
      { key: `read:${PROJECT_A}`, value: "A (read)", group: "A" },
      { key: `write:${PROJECT_A}`, value: "A (write)", group: "A" },
      { key: `read:${PROJECT_B}`, value: "B (read)", group: "B" },
      { key: `write:${PROJECT_B}`, value: "B (write)", group: "B" },
    ]);
  });
});
