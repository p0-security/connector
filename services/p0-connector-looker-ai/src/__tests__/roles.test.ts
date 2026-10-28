import { ConnectorError } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../looker/looker-api.ts";
import {
  LEVEL_PERMISSIONS,
  closeOverParents,
  setModelRole,
  toLevelPermissions,
  toModelSetName,
  toPermissionSetName,
  toRoleName,
} from "../roles.ts";

vi.mock("../looker/looker-api.ts");

const SESSION = { baseUrl: "https://example.looker.app", accessToken: "t" };

// Looker's own permissions, in part: each with the one it depends on.
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
  ["develop", "explore"],
  ["manage_models", null],
]);

const READ = [
  "access_data",
  "explore",
  "see_lookml_dashboards",
  "see_looks",
  "see_sql",
  "see_user_dashboards",
];
const EDIT = [...READ, "save_content", "save_dashboards", "save_looks"].sort();

type Stored = {
  permissionSets: api.LookerPermissionSet[];
  modelSets: api.LookerModelSet[];
  roles: api.LookerRole[];
};

/** The fake instance's objects, and what each create call stored. */
const looker: Stored = { permissionSets: [], modelSets: [], roles: [] };
let nextId = 1;
const created: string[] = [];

const byName =
  <K extends keyof Stored>(kind: K) =>
  async (_: unknown, name: string): Promise<Stored[K][number] | undefined> =>
    looker[kind].find((object) => object.name === name);

const store = <K extends keyof Stored>(
  kind: K,
  object: Omit<Stored[K][number], "id">
): Stored[K][number] => {
  const withId = { ...object, id: String(nextId++) } as Stored[K][number];
  (looker[kind] as Stored[K][number][]).push(withId);
  created.push(`${kind} ${object.name}`);
  return withId;
};

const taken = (name: string) =>
  new ConnectorError({
    type: "already_exists",
    message: `taken: ${name}`,
    payload: {},
  });

beforeEach(() => {
  vi.resetAllMocks();
  looker.permissionSets = [];
  looker.modelSets = [];
  looker.roles = [];
  nextId = 1;
  created.length = 0;

  vi.mocked(api.listPermissionParents).mockResolvedValue(new Map(PARENTS));
  vi.mocked(api.findPermissionSet).mockImplementation(byName("permissionSets"));
  vi.mocked(api.findModelSet).mockImplementation(byName("modelSets"));
  vi.mocked(api.findRole).mockImplementation(byName("roles"));
  vi.mocked(api.createPermissionSet).mockImplementation(async (_, set) =>
    store("permissionSets", set)
  );
  vi.mocked(api.createModelSet).mockImplementation(async (_, set) =>
    store("modelSets", set)
  );
  vi.mocked(api.createRole).mockImplementation(async (_, role) =>
    store("roles", {
      name: role.name,
      permissionSetId: role.permissionSetId,
      modelSetId: role.modelSetId,
    })
  );
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

describe("closeOverParents", () => {
  it("adds each permission's parents, and theirs", () => {
    expect(closeOverParents(["save_dashboards"], PARENTS)).toEqual({
      permissions: [
        "access_data",
        "save_dashboards",
        "see_looks",
        "see_user_dashboards",
      ],
      missing: [],
    });
  });

  it("reports a permission the instance doesn't list, and a parent it doesn't", () => {
    const parents = new Map([["explore", "see_everything"]]);

    expect(closeOverParents(["explore", "save_content"], parents)).toEqual({
      permissions: ["explore"],
      missing: ["save_content", "see_everything"],
    });
  });

  it("stops at a parent chain that loops", () => {
    const parents = new Map([
      ["a", "b"],
      ["b", "a"],
    ]);

    expect(closeOverParents(["a"], parents).permissions).toEqual(["a", "b"]);
  });
});

describe("toLevelPermissions", () => {
  it.each([
    ["read", READ],
    ["edit", EDIT],
  ] as const)("closes %s over the instance's parents", (level, permissions) => {
    expect(toLevelPermissions(level, PARENTS)).toEqual(permissions);
  });

  it("asks edit for everything read asks for", () => {
    for (const permission of LEVEL_PERMISSIONS.read)
      expect(LEVEL_PERMISSIONS.edit).toContain(permission);
  });

  it("fails when the instance lacks a permission, and names it", async () => {
    const parents = new Map(PARENTS);
    parents.delete("save_content");

    const data = await connectorError(async () =>
      toLevelPermissions("edit", parents)
    );

    expect(data.message).toBe(
      "The Looker instance doesn't have the permissions that P0's edit level needs: save_content"
    );
    expect(data.payload).toEqual({ level: "edit", missing: "save_content" });
  });

  it.each(["administer", "deploy", "develop", "manage_models", "sudo"])(
    "fails when %s would come in as a parent",
    async (refused) => {
      const parents = new Map(PARENTS)
        .set("explore", refused)
        .set(refused, null);

      const data = await connectorError(async () =>
        toLevelPermissions("read", parents)
      );

      expect(data.message).toBe(
        `On this Looker instance, P0's read level would include ${refused}, which P0 never grants`
      );
    }
  );

  it("names every permission the instance lacks", async () => {
    const parents = new Map(PARENTS);
    parents.delete("save_looks");
    parents.delete("save_content");

    const data = await connectorError(async () =>
      toLevelPermissions("edit", parents)
    );

    expect(data).toEqual({
      type: "unknown",
      message:
        "The Looker instance doesn't have the permissions that P0's edit level needs: save_content, save_looks",
      payload: { level: "edit", missing: "save_content,save_looks" },
    });
  });

  it("names every refused permission that would come in", async () => {
    const parents = new Map(PARENTS)
      .set("explore", "develop")
      .set("develop", "sudo")
      .set("sudo", null);

    const data = await connectorError(async () =>
      toLevelPermissions("read", parents)
    );

    expect(data).toEqual({
      type: "unknown",
      message:
        "On this Looker instance, P0's read level would include develop, sudo, which P0 never grants",
      payload: { level: "read", refused: "develop,sudo" },
    });
  });
});

describe("names", () => {
  it("are P0's", () => {
    expect(toPermissionSetName("read")).toBe("p0-looker-ai-read");
    expect(toModelSetName("the_look")).toBe("p0-looker-ai-model-the_look");
    expect(toRoleName("the_look", "edit")).toBe("p0-looker-ai-the_look-edit");
  });

  // A model whose name ends like a level must not share a role.
  it("give each model and level its own role", () => {
    const names = ["a", "a-read", "a-edit", "a-read-edit"].flatMap((model) =>
      (["read", "edit"] as const).map((level) => toRoleName(model, level))
    );

    expect(new Set(names).size).toBe(names.length);
  });
});

describe("setModelRole", () => {
  const grant = (model = "the_look", level: "edit" | "read" = "read") =>
    setModelRole(SESSION, { model, level });

  it("creates the permission set, the model set and the role", async () => {
    const roleId = await grant();

    expect(looker).toEqual({
      permissionSets: [
        { id: "1", name: "p0-looker-ai-read", permissions: READ },
      ],
      modelSets: [
        { id: "2", name: "p0-looker-ai-model-the_look", models: ["the_look"] },
      ],
      roles: [
        {
          id: "3",
          name: "p0-looker-ai-the_look-read",
          permissionSetId: "1",
          modelSetId: "2",
        },
      ],
    });
    expect(roleId).toBe("3");
  });

  it("reuses what an earlier grant made", async () => {
    const first = await grant();
    created.length = 0;

    await expect(grant()).resolves.toBe(first);
    expect(created).toEqual([]);
  });

  it("shares the permission set between models, and the model set between levels", async () => {
    await grant("the_look", "read");
    await grant("orders", "read");
    await grant("orders", "edit");

    expect(created).toEqual([
      "permissionSets p0-looker-ai-read",
      "modelSets p0-looker-ai-model-the_look",
      "roles p0-looker-ai-the_look-read",
      "modelSets p0-looker-ai-model-orders",
      "roles p0-looker-ai-orders-read",
      "permissionSets p0-looker-ai-edit",
      "roles p0-looker-ai-orders-edit",
    ]);
  });

  it("creates nothing when the instance lacks a permission", async () => {
    const parents = new Map(PARENTS);
    parents.delete("explore");
    vi.mocked(api.listPermissionParents).mockResolvedValue(parents);

    await expect(grant()).rejects.toThrow("needs: explore");
    expect(created).toEqual([]);
  });

  describe("when a Looker admin changed what P0 made", () => {
    beforeEach(async () => {
      await grant();
      created.length = 0;
    });

    it.each<[string, () => void, string]>([
      [
        "a permission added to the permission set",
        () => looker.permissionSets[0]?.permissions.push("develop"),
        "The Looker permission set p0-looker-ai-read isn't the one P0 made: it also has develop. P0 won't grant access with it. Change it back, or delete it so that P0 makes it again.",
      ],
      [
        "a permission taken from the permission set",
        () => looker.permissionSets[0]?.permissions.splice(0, 1),
        "The Looker permission set p0-looker-ai-read isn't the one P0 made: it lacks access_data. P0 won't grant access with it. Change it back, or delete it so that P0 makes it again.",
      ],
      [
        "a model added to the model set",
        () => looker.modelSets[0]?.models.push("finance"),
        "The Looker model set p0-looker-ai-model-the_look isn't the one P0 made: it also has finance. P0 won't grant access with it. Change it back, or delete it so that P0 makes it again.",
      ],
      [
        "the role's permission set",
        () => Object.assign(looker.roles[0] ?? {}, { permissionSetId: "99" }),
        "The Looker role p0-looker-ai-the_look-read isn't the one P0 made: its permission set isn't p0-looker-ai-read. P0 won't grant access with it. Change it back, or delete it so that P0 makes it again.",
      ],
      [
        "the role's model set",
        () => Object.assign(looker.roles[0] ?? {}, { modelSetId: "99" }),
        "The Looker role p0-looker-ai-the_look-read isn't the one P0 made: its model set isn't p0-looker-ai-model-the_look. P0 won't grant access with it. Change it back, or delete it so that P0 makes it again.",
      ],
      [
        "the role, so that Looker leaves its sets out",
        () =>
          Object.assign(looker.roles[0] ?? {}, {
            permissionSetId: undefined,
            modelSetId: undefined,
          }),
        "The Looker role p0-looker-ai-the_look-read isn't the one P0 made: its permission set isn't p0-looker-ai-read; its model set isn't p0-looker-ai-model-the_look. P0 won't grant access with it. Change it back, or delete it so that P0 makes it again.",
      ],
    ])("fails for %s, and changes nothing", async (_, change, message) => {
      change();

      const data = await connectorError(() => grant());

      expect(data.type).toBe("unknown");
      expect(data.message).toBe(message);
      expect(created).toEqual([]);
    });

    it("names the object it refuses in the payload", async () => {
      looker.permissionSets[0]?.permissions.push("develop");

      const data = await connectorError(() => grant());

      expect(data.payload).toEqual({
        kind: "permission set",
        name: "p0-looker-ai-read",
      });
    });

    it("lists every permission added, in order, whatever order Looker keeps them in", async () => {
      looker.permissionSets[0]?.permissions.push(
        "see_drill_overlay",
        "develop"
      );

      await expect(grant()).rejects.toThrow(
        "it also has develop, see_drill_overlay."
      );
    });

    it("lists every permission taken away", async () => {
      looker.permissionSets[0]?.permissions.splice(0, 2);

      await expect(grant()).rejects.toThrow("it lacks access_data, explore.");
    });
  });

  // For example, if Looker added a permission of its own on create.
  it("fails when Looker creates something other than what P0 asked for", async () => {
    vi.mocked(api.createPermissionSet).mockImplementation(async (_, set) =>
      store("permissionSets", {
        ...set,
        permissions: [...set.permissions, "see_drill_overlay"],
      })
    );

    await expect(grant()).rejects.toThrow("it also has see_drill_overlay");
    expect(api.createModelSet).not.toHaveBeenCalled();
  });

  describe("when another grant creates the same object first", () => {
    it.each([
      ["permission set", api.createPermissionSet, api.findPermissionSet],
      ["model set", api.createModelSet, api.findModelSet],
      ["role", api.createRole, api.findRole],
    ] as const)("uses the other grant's %s", async (_, create, find) => {
      // The search misses the other grant's object, and the create finds it.
      const real = vi.mocked(create).getMockImplementation();
      vi.mocked(find).mockResolvedValueOnce(undefined);
      vi.mocked(create).mockImplementationOnce(async (session, object) => {
        await (real as typeof create)(session, object as never);
        throw taken(object.name);
      });

      const first = await grant();

      expect(create).toHaveBeenCalledTimes(1);
      expect(find).toHaveBeenCalledTimes(2);
      // The object the other grant made, and only one of it.
      await expect(grant()).resolves.toBe(first);
      expect(looker.roles).toHaveLength(1);
    });

    it("fails when the search still finds nothing", async () => {
      vi.mocked(api.createRole).mockRejectedValue(taken("role"));

      const data = await connectorError(() => grant());

      expect(data).toEqual({
        type: "already_exists",
        message: "taken: role",
        payload: {},
      });
    });
  });

  it("propagates any other failure to create", async () => {
    vi.mocked(api.createModelSet).mockRejectedValue(
      new ConnectorError({
        type: "insufficient_privileges",
        message: "no",
        payload: {},
      })
    );

    const data = await connectorError(() => grant());

    expect(data.type).toBe("insufficient_privileges");
    expect(api.findModelSet).toHaveBeenCalledTimes(1);
    expect(api.createRole).not.toHaveBeenCalled();
  });
});
