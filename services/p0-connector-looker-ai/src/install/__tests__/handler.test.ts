import { ConnectorError, createLogger } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../../looker/looker-api.ts";
import { connectorRouter } from "../../router.ts";

vi.mock("../../looker/looker-api.ts");

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const secretManager = vi.hoisted(() => ({ create: vi.fn() }));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => ({
  ...(await importOriginal<typeof SecretManagerClientModule>()),
  createSecretManagerClient: secretManager.create,
}));

const BASE_URL = "https://example.looker.app";
const ADMIN_KEY = { client_id: "admin-id", client_secret: "admin-secret" };
const SESSION = { baseUrl: BASE_URL, accessToken: "admin-token" };

const INSTALL = {
  baseUrl: BASE_URL,
  secrets: {
    manager: "gcp" as const,
    adminKeySecretId: "p0_install_looker_acme_admin-key",
    projectId: "acme-prod",
  },
};

const PARENTS = new Map<string, string | null>([
  ["access_data", null],
  ["see_looks", "access_data"],
  ["see_user_dashboards", "see_looks"],
  ["see_lookml_dashboards", "access_data"],
  ["explore", "see_looks"],
  ["see_sql", "access_data"],
  ["save_content", "see_looks"],
  ["save_looks", "see_looks"],
  ["save_dashboards", "see_user_dashboards"],
]);

const validate = (input: Record<string, unknown> = INSTALL) => {
  const log = createLogger();
  log.level = "silent";
  return connectorRouter
    .createCaller({ logger: log })
    ["looker-ai"].install.validation.get(input as typeof INSTALL);
};

beforeEach(() => {
  vi.resetAllMocks();
  secretManager.create.mockResolvedValue({
    getSecretValue: async () => ({ value: JSON.stringify(ADMIN_KEY) }),
  });
  vi.mocked(api.login).mockResolvedValue(SESSION);
  vi.mocked(api.logout).mockResolvedValue();
  vi.mocked(api.listModels).mockResolvedValue([
    { name: "thelook", label: "The Look" },
    { name: "orders", label: "Orders" },
  ]);
  vi.mocked(api.listPermissionParents).mockResolvedValue(new Map(PARENTS));
  vi.mocked(api.listGroupsWithRoles).mockResolvedValue([
    { id: "1", name: "All Users", includeByDefault: true, roles: [] },
    { id: "2", name: "BI", includeByDefault: false, roles: ["Viewer"] },
  ]);
  vi.mocked(api.findFolder).mockResolvedValue({ contentMetadataId: "cm-7" });
});

describe("install.validation.get", () => {
  it("passes an instance with everything P0 needs", async () => {
    await expect(validate()).resolves.toEqual({
      adminKeyAccepted: true,
      models: 2,
      missingPermissions: [],
      refusedPermissions: [],
      inheritedRoles: [],
      contentFolderFound: null,
    });
    expect(api.login).toHaveBeenCalledWith(BASE_URL, ADMIN_KEY);
    expect(api.logout).toHaveBeenCalledWith(SESSION);
    expect(api.findFolder).not.toHaveBeenCalled();
  });

  it("reports the Admin key when Looker doesn't accept it, and checks nothing else", async () => {
    vi.mocked(api.login).mockRejectedValue(
      new ConnectorError({
        type: "insufficient_privileges",
        message: "rejected",
        payload: { status: 404, reason: "admin_key_rejected" },
      })
    );

    await expect(validate()).resolves.toEqual({
      adminKeyAccepted: false,
      models: 0,
      missingPermissions: [],
      refusedPermissions: [],
      inheritedRoles: [],
      contentFolderFound: null,
    });
    expect(api.listModels).not.toHaveBeenCalled();
  });

  it("fails on any other error, such as a key without the Admin role", async () => {
    vi.mocked(api.listGroupsWithRoles).mockRejectedValue(
      new ConnectorError({
        type: "insufficient_privileges",
        message: "Looker GET /groups/search/with_roles failed (403): Forbidden",
        payload: { status: 403 },
      })
    );

    await expect(validate()).rejects.toThrow("(403): Forbidden");
  });

  it("counts the models a grant can name", async () => {
    vi.mocked(api.listModels).mockResolvedValue([]);

    await expect(validate()).resolves.toMatchObject({ models: 0 });
  });

  it("reports the permissions either level needs that the instance lacks", async () => {
    const parents = new Map(PARENTS);
    parents.delete("save_content");
    parents.set("explore", "see_everything");
    vi.mocked(api.listPermissionParents).mockResolvedValue(parents);

    await expect(validate()).resolves.toMatchObject({
      missingPermissions: ["save_content", "see_everything"],
    });
  });

  it("reports a refused permission that comes in as a parent", async () => {
    const parents = new Map(PARENTS)
      .set("save_looks", "develop")
      .set("develop", null);
    vi.mocked(api.listPermissionParents).mockResolvedValue(parents);

    await expect(validate()).resolves.toMatchObject({
      refusedPermissions: ["develop"],
    });
  });

  // set_user_roles can't take them away (W2, W6).
  it("reports the roles of the groups every new account joins", async () => {
    vi.mocked(api.listGroupsWithRoles).mockResolvedValue([
      { id: "1", name: "All Users", includeByDefault: true, roles: ["Viewer"] },
      { id: "2", name: "BI", includeByDefault: false, roles: ["Admin"] },
      { id: "3", name: "Everyone", includeByDefault: true, roles: [] },
      {
        id: "4",
        name: "Staff",
        includeByDefault: true,
        roles: ["User", "Viewer"],
      },
    ]);

    await expect(validate()).resolves.toMatchObject({
      inheritedRoles: [
        { group: "All Users", roles: ["Viewer"] },
        { group: "Staff", roles: ["User", "Viewer"] },
      ],
    });
  });

  it.each([
    [{ contentMetadataId: "cm-7" }, true],
    [undefined, false],
  ])(
    "reports whether the agent content folder exists",
    async (found, exists) => {
      vi.mocked(api.findFolder).mockResolvedValue(found);

      await expect(
        validate({ ...INSTALL, contentFolderId: "42" })
      ).resolves.toMatchObject({ contentFolderFound: exists });
      expect(api.findFolder).toHaveBeenCalledWith(SESSION, "42");
    }
  );

  it.each([
    ["an instance URL on another host", { baseUrl: "https://evil.example" }],
    ["a folder id that is a path", { contentFolderId: "../users" }],
  ])("refuses %s before signing in", async (_, change) => {
    await expect(validate({ ...INSTALL, ...change })).rejects.toThrow();

    expect(api.login).not.toHaveBeenCalled();
  });
});
