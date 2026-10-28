import { createLogger } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/secret-manager-client";
import type { SecretRef } from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { t } from "../../../router.ts";
import * as clientModule from "../../../servicenow/client.ts";
import { router } from "../handler.ts";

vi.mock("../../../servicenow/client.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof clientModule>()),
  newProvisionerClient: vi.fn(),
  mintUserToken: vi.fn(),
}));

const INSTALL_SECRET = "p0_install_servicenow_acme_install";
const TOKEN_SECRET = "p0_access-token_servicenow_acme_abc";
const SYS_ID = "a".repeat(32);

const secrets = new Map<string, string[]>();
const secretManager = {
  getSecretValue: vi.fn(async ({ ref }: { ref: string }) => ({
    value: secrets.get(ref)!.at(-1)!,
  })),
  getSecret: vi.fn(),
  createSecret: vi.fn(),
  createSecretVersion: vi.fn(),
  deleteSecret: vi.fn(),
};

const { secretManagerConfigs } = vi.hoisted(() => ({
  secretManagerConfigs: [] as unknown[],
}));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => {
  const actual = await importOriginal<typeof SecretManagerClientModule>();
  return {
    ...actual,
    createSecretManagerClient: async (config: unknown) => {
      secretManagerConfigs.push(config);
      return secretManager;
    },
  };
});

const { SecretNotFoundError } = await vi.importActual<
  typeof SecretManagerClientModule
>("@p0security/secret-manager-client");

const provisioner = {
  findUser: vi.fn(),
  getUser: vi.fn(),
  createUser: vi.fn(),
  deleteUser: vi.fn(),
  userRoles: vi.fn(),
  addRole: vi.fn(),
  removeRole: vi.fn(),
  listRoles: vi.fn(),
};

const instance = {
  domain: "acme.service-now.com",
  provisionerClientId: "prov-client",
  jwtClientId: "jwt-client",
  keyId: "p0-key",
  secrets: {
    manager: "gcp" as const,
    installSecretId: INSTALL_SECRET,
    projectId: "p",
  },
};

const context = {
  requestId: "r-1",
  tokenSecretName: TOKEN_SECRET,
  ...instance,
};

const caller = () => router(t).createCaller({ logger: createLogger() });

const notFound = () => new SecretNotFoundError(TOKEN_SECRET as SecretRef);

beforeEach(() => {
  vi.clearAllMocks();
  secrets.clear();
  secretManagerConfigs.length = 0;
  secrets.set(INSTALL_SECRET, [
    JSON.stringify({
      provisionerClientSecret: "prov-secret",
      jwtClientSecret: "jwt-secret",
      signingKey:
        "-----BEGIN PRIVATE KEY-----\\nkey\\n-----END PRIVATE KEY-----",
    }),
  ]);
  vi.mocked(clientModule.newProvisionerClient).mockResolvedValue(provisioner);
  vi.mocked(clientModule.mintUserToken).mockResolvedValue("user-token");
  provisioner.getUser.mockResolvedValue({
    sysId: SYS_ID,
    userName: "p0-agent-abc",
  });
});

describe("provisionUser", () => {
  it("uses the session's user when it exists", async () => {
    provisioner.findUser.mockResolvedValue({
      sysId: SYS_ID,
      userName: "p0-agent-abc",
    });

    await expect(
      caller().provisionUser({ userBody: "abc", context })
    ).resolves.toBe(SYS_ID);
    expect(provisioner.findUser).toHaveBeenCalledWith("p0-agent-abc");
    expect(provisioner.createUser).not.toHaveBeenCalled();
    expect(clientModule.newProvisionerClient).toHaveBeenCalledWith({
      domain: "acme.service-now.com",
      clientId: "prov-client",
      clientSecret: "prov-secret",
    });
  });

  it("creates the session's user when it is missing", async () => {
    provisioner.findUser.mockResolvedValue(null);
    provisioner.createUser.mockResolvedValue(SYS_ID);

    await expect(
      caller().provisionUser({ userBody: "abc", context })
    ).resolves.toBe(SYS_ID);
    expect(provisioner.createUser).toHaveBeenCalledWith("p0-agent-abc");
  });

  it("refuses an agent key that does not fit in user_name", async () => {
    await expect(
      caller().provisionUser({ userBody: "a".repeat(32), context })
    ).rejects.toThrow();
    expect(provisioner.createUser).not.toHaveBeenCalled();
  });
});

describe("setPoliciesForUser", () => {
  it("makes the user hold exactly the roles, then writes a new token", async () => {
    provisioner.userRoles
      .mockResolvedValueOnce([
        { rowId: "keep", roleName: "itil" },
        { rowId: "drop", roleName: "knowledge" },
      ])
      .mockResolvedValueOnce([
        { rowId: "keep", roleName: "itil" },
        { rowId: "new", roleName: "approver_user" },
      ]);
    secretManager.getSecret.mockRejectedValue(notFound());

    await caller().setPoliciesForUser({
      userId: SYS_ID,
      userBody: "abc",
      policies: ["itil", "approver_user", "itil"],
      context,
    });

    expect(provisioner.removeRole).toHaveBeenCalledExactlyOnceWith("drop");
    expect(provisioner.addRole).toHaveBeenCalledExactlyOnceWith(
      SYS_ID,
      "approver_user"
    );
    expect(clientModule.mintUserToken).toHaveBeenCalledWith(
      {
        domain: "acme.service-now.com",
        clientId: "jwt-client",
        clientSecret: "jwt-secret",
        signingKey:
          "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        keyId: "p0-key",
      },
      "p0-agent-abc"
    );
    expect(secretManager.createSecret).toHaveBeenCalledWith({
      name: TOKEN_SECRET,
    });
    expect(secretManager.createSecretVersion).toHaveBeenCalledWith({
      ref: TOKEN_SECRET,
      type: "value",
      value: Buffer.from("user-token"),
    });
  });

  it("adds a version to the token secret when it exists", async () => {
    provisioner.userRoles.mockResolvedValue([{ rowId: "r", roleName: "itil" }]);
    secretManager.getSecret.mockResolvedValue({ ref: TOKEN_SECRET });

    await caller().setPoliciesForUser({
      userId: SYS_ID,
      userBody: "abc",
      policies: ["itil"],
      context,
    });

    expect(secretManager.createSecret).not.toHaveBeenCalled();
    expect(secretManager.createSecretVersion).toHaveBeenCalled();
  });

  it("fails, and writes no token, when ServiceNow drops a role", async () => {
    provisioner.userRoles
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ rowId: "empty", roleName: "" }]);

    await expect(
      caller().setPoliciesForUser({
        userId: SYS_ID,
        userBody: "abc",
        policies: ["sn_esm_admin"],
        context,
      })
    ).rejects.toThrow("ServiceNow did not grant these roles");

    expect(provisioner.removeRole).toHaveBeenCalledWith("empty");
    expect(clientModule.mintUserToken).not.toHaveBeenCalled();
    expect(secretManager.createSecretVersion).not.toHaveBeenCalled();
  });

  it.each(["admin", "security_admin", "user_admin"])(
    "refuses %s before it calls ServiceNow",
    async (role) => {
      await expect(
        caller().setPoliciesForUser({
          userId: SYS_ID,
          userBody: "abc",
          policies: ["itil", role],
          context,
        })
      ).rejects.toThrow("P0 does not grant these ServiceNow roles");
      expect(provisioner.addRole).not.toHaveBeenCalled();
    }
  );

  it("removes every role and the token for no roles", async () => {
    provisioner.userRoles
      .mockResolvedValueOnce([{ rowId: "r", roleName: "itil" }])
      .mockResolvedValueOnce([]);

    await caller().setPoliciesForUser({
      userId: SYS_ID,
      userBody: "abc",
      policies: [],
      context,
    });

    expect(provisioner.removeRole).toHaveBeenCalledWith("r");
    expect(secretManager.deleteSecret).toHaveBeenCalledWith({
      ref: TOKEN_SECRET,
    });
    expect(clientModule.mintUserToken).not.toHaveBeenCalled();
  });

  it("refuses a user that P0 did not create", async () => {
    provisioner.getUser.mockResolvedValue({ sysId: SYS_ID, userName: "admin" });

    await expect(
      caller().setPoliciesForUser({
        userId: SYS_ID,
        userBody: "abc",
        policies: ["itil"],
        context,
      })
    ).rejects.toThrow("is not namespaced");
    expect(provisioner.userRoles).not.toHaveBeenCalled();
  });
});

describe("deleteUser", () => {
  it("deletes the user and its token secret", async () => {
    await caller().deleteUser({ userId: SYS_ID, userBody: "abc", context });

    expect(provisioner.deleteUser).toHaveBeenCalledWith(SYS_ID);
    expect(secretManager.deleteSecret).toHaveBeenCalledWith({
      ref: TOKEN_SECRET,
    });
  });

  it("succeeds when the token secret is already gone", async () => {
    secretManager.deleteSecret.mockRejectedValue(notFound());

    await expect(
      caller().deleteUser({ userId: SYS_ID, userBody: "abc", context })
    ).resolves.toBeNull();
  });
});

describe("list", () => {
  it("lists the roles that P0 may grant", async () => {
    provisioner.listRoles.mockResolvedValue(["admin", "approver_user", "itil"]);

    await expect(
      caller().list({ query: { type: "role", context: instance } })
    ).resolves.toEqual([
      { key: "approver_user", value: "approver_user" },
      { key: "itil", value: "itil" },
    ]);
  });
});

describe("secret manager", () => {
  it.each([
    [
      "AWS Secrets Manager",
      { manager: "aws" as const, region: "us-west-2" },
      { provider: "aws", region: "us-west-2" },
    ],
    [
      "Google Secret Manager",
      { manager: "gcp" as const, projectId: "p" },
      { provider: "gcp", projectId: "p" },
    ],
  ])("reads the install secret from %s", async (_, manager, config) => {
    provisioner.listRoles.mockResolvedValue([]);

    await caller().list({
      query: {
        type: "role",
        context: {
          ...instance,
          secrets: { ...manager, installSecretId: INSTALL_SECRET },
        },
      },
    });

    expect(secretManagerConfigs).toEqual([config]);
    expect(clientModule.newProvisionerClient).toHaveBeenCalledWith(
      expect.objectContaining({ clientSecret: "prov-secret" })
    );
  });
});
