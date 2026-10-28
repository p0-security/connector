import { ConnectorError, createLogger } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { DriveApi, DriveFile } from "../../../drive/api.ts";
import { newDriveResourcePrimitives } from "../handler.ts";

const DRIVE_ID = "0ABCdefGHIjklUk9PVA";
const FILE_ID = "1XyZ_folder_id";
const PROJECT_ID = "p0-agentic-identities";
const GRANTEE = `p0a-agile-otter-1f2e3d4c@${PROJECT_ID}.iam.gserviceaccount.com`;
const HUMAN = "dominick.hing@p0.dev";

const CONTEXT = {
  requestId: "req-1",
  driveId: DRIVE_ID,
  projectId: PROJECT_ID,
};

const FOLDER: DriveFile = {
  id: FILE_ID,
  name: "Quarterly reports",
  mimeType: "application/vnd.google-apps.folder",
  driveId: DRIVE_ID,
};

const logger = createLogger();
logger.level = "silent";

const newApi = () => ({
  getFile: vi.fn<DriveApi["getFile"]>().mockResolvedValue(FOLDER),
  listFiles: vi.fn<DriveApi["listFiles"]>().mockResolvedValue([FOLDER]),
  listPermissions: vi.fn<DriveApi["listPermissions"]>().mockResolvedValue([]),
  createPermission: vi.fn<DriveApi["createPermission"]>().mockResolvedValue(),
  updatePermission: vi.fn<DriveApi["updatePermission"]>().mockResolvedValue(),
  deletePermission: vi.fn<DriveApi["deletePermission"]>().mockResolvedValue(),
});

type FakeApi = ReturnType<typeof newApi>;

let api: FakeApi;
let perimeter: ReturnType<typeof newDriveResourcePrimitives>;

const errorType = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    if (error instanceof ConnectorError) return error.data;
    throw error;
  }
  throw new Error("expected the call to throw");
};

beforeEach(() => {
  api = newApi();
  perimeter = newDriveResourcePrimitives(logger, api);
});

describe("setPoliciesForUser", () => {
  const converge = (role: "reader" | "writer" | null) =>
    perimeter.setPoliciesForUser(CONTEXT, GRANTEE, GRANTEE, [
      { resourceId: FILE_ID, role },
    ]);

  it("creates the entry when the grantee has none", async () => {
    await converge("writer");

    expect(api.createPermission).toHaveBeenCalledWith(
      FILE_ID,
      GRANTEE,
      "writer"
    );
    expect(api.updatePermission).not.toHaveBeenCalled();
    expect(api.deletePermission).not.toHaveBeenCalled();
  });

  it("updates the role when the entry exists at a different one", async () => {
    api.listPermissions.mockResolvedValue([
      { id: "perm-1", role: "reader", emailAddress: GRANTEE },
    ]);

    await converge("writer");

    expect(api.updatePermission).toHaveBeenCalledWith(
      FILE_ID,
      "perm-1",
      "writer"
    );
    expect(api.createPermission).not.toHaveBeenCalled();
  });

  it("writes nothing when the entry is already at the requested role", async () => {
    api.listPermissions.mockResolvedValue([
      { id: "perm-1", role: "writer", emailAddress: GRANTEE },
    ]);

    await converge("writer");

    expect(api.createPermission).not.toHaveBeenCalled();
    expect(api.updatePermission).not.toHaveBeenCalled();
    expect(api.deletePermission).not.toHaveBeenCalled();
  });

  // Revocation is expressed as a null role, not as a delete endpoint.
  it("deletes the entry when the role is null", async () => {
    api.listPermissions.mockResolvedValue([
      { id: "perm-1", role: "writer", emailAddress: GRANTEE },
    ]);

    await converge(null);

    expect(api.deletePermission).toHaveBeenCalledWith(FILE_ID, "perm-1");
  });

  it("is a no-op when a null role finds no entry", async () => {
    await converge(null);

    expect(api.deletePermission).not.toHaveBeenCalled();
  });

  // The ~30s clock is authorization propagation to the grantee's token, not the
  // metadata commit made here, so a read-back would measure the wrong thing.
  it("never reads back its own write", async () => {
    await converge("writer");

    expect(api.listPermissions).toHaveBeenCalledTimes(1);
    expect(api.listPermissions.mock.invocationCallOrder[0]).toBeLessThan(
      api.createPermission.mock.invocationCallOrder[0]
    );
  });

  it("matches the grantee's entry regardless of address case", async () => {
    api.listPermissions.mockResolvedValue([
      { id: "perm-1", role: "reader", emailAddress: GRANTEE.toUpperCase() },
    ]);

    await converge("writer");

    expect(api.updatePermission).toHaveBeenCalledWith(
      FILE_ID,
      "perm-1",
      "writer"
    );
  });

  it("refuses an entry with a role it cannot have set", async () => {
    api.listPermissions.mockResolvedValue([
      { id: "perm-1", role: "organizer", emailAddress: GRANTEE },
    ]);

    const data = await errorType(() => converge("writer"));

    expect(data.type).toBe("dependency_violation");
    expect(api.createPermission).not.toHaveBeenCalled();
    expect(api.updatePermission).not.toHaveBeenCalled();
  });

  it("refuses to revoke an entry with a role it cannot have set", async () => {
    api.listPermissions.mockResolvedValue([
      { id: "perm-1", role: "organizer", emailAddress: GRANTEE },
    ]);

    const data = await errorType(() => converge(null));

    expect(data.type).toBe("dependency_violation");
    expect(api.deletePermission).not.toHaveBeenCalled();
  });

  // Any other count is a P0 backend bug, not a customer error, so it must not
  // surface as a validation error.
  it.each([
    ["none", []],
    [
      "two",
      [
        { resourceId: FILE_ID, role: "reader" as const },
        { resourceId: FILE_ID, role: "writer" as const },
      ],
    ],
  ])("refuses %s policies, as an internal error", async (_, policies) => {
    const data = await errorType(() =>
      perimeter.setPoliciesForUser(CONTEXT, GRANTEE, GRANTEE, policies)
    );

    expect(data.type).toBe("unknown");
    expect(api.getFile).not.toHaveBeenCalled();
    expect(api.createPermission).not.toHaveBeenCalled();
  });
});

describe("setPoliciesForUser containment", () => {
  it("refuses an item in another drive", async () => {
    api.getFile.mockResolvedValue({ ...FOLDER, driveId: "0AotherDriveId" });

    const data = await errorType(() =>
      perimeter.setPoliciesForUser(CONTEXT, GRANTEE, GRANTEE, [
        { resourceId: FILE_ID, role: "writer" },
      ])
    );

    expect(data.type).toBe("validation_error");
    expect(api.listPermissions).not.toHaveBeenCalled();
    expect(api.createPermission).not.toHaveBeenCalled();
  });

  // A permissions.create on a drive id is a membership mutation, and Drive
  // silently swallows a concurrent folder grant to a principal that is a member.
  it("refuses the drive root", async () => {
    api.getFile.mockResolvedValue({
      id: DRIVE_ID,
      name: "Engineering",
      mimeType: "application/vnd.google-apps.folder",
      driveId: DRIVE_ID,
    });

    const data = await errorType(() =>
      perimeter.setPoliciesForUser(CONTEXT, GRANTEE, GRANTEE, [
        { resourceId: DRIVE_ID, role: "writer" },
      ])
    );

    expect(data.type).toBe("validation_error");
    expect(api.createPermission).not.toHaveBeenCalled();
  });

  it("reports an unresolvable id without claiming to know why", async () => {
    api.getFile.mockResolvedValue(undefined);

    const data = await errorType(() =>
      perimeter.setPoliciesForUser(CONTEXT, GRANTEE, GRANTEE, [
        { resourceId: FILE_ID, role: "writer" },
      ])
    );

    expect(data.type).toBe("object_not_found");
    expect(data.message).toContain(
      "not found in any shared drive this connector manages"
    );
    expect(data.payload.query).toBe(FILE_ID);
  });
});

describe("list", () => {
  const list = () =>
    perimeter.list({
      type: "resource" as const,
      context: { driveId: DRIVE_ID },
    });

  it("lists the drive's items, each with its kind", async () => {
    api.listFiles.mockResolvedValue([
      FOLDER,
      {
        ...FOLDER,
        id: "1doc",
        mimeType: "application/vnd.google-apps.document",
      },
    ]);

    await expect(list()).resolves.toEqual([
      { key: FILE_ID, value: "Quarterly reports", group: "folder" },
      { key: "1doc", value: "Quarterly reports", group: "file" },
    ]);
    expect(api.listFiles).toHaveBeenCalledWith(DRIVE_ID);
  });

  it("omits items from another drive and the drive root", async () => {
    api.listFiles.mockResolvedValue([
      { ...FOLDER, driveId: "0AotherDriveId" },
      { ...FOLDER, id: DRIVE_ID },
    ]);

    await expect(list()).resolves.toEqual([]);
  });
});

describe("user primitives", () => {
  it("getUser returns the address it was given", async () => {
    await expect(perimeter.getUser(CONTEXT, GRANTEE)).resolves.toBe(GRANTEE);
  });

  // Unreachable behind the framework's get-or-create, and loudly so.
  it("createUser throws", async () => {
    const data = await errorType(() => perimeter.createUser(CONTEXT, GRANTEE));

    expect(data.type).toBe("unknown");
    expect(data.message).toContain("cannot create identities");
  });

  // One identity is shared across a session's grants to different folders, so
  // destroying it here would break a live grant elsewhere.
  it("deleteUser touches nothing", async () => {
    await expect(
      perimeter.deleteUser(CONTEXT, GRANTEE, GRANTEE)
    ).resolves.toBeUndefined();

    expect(api.deletePermission).not.toHaveBeenCalled();
    expect(api.getFile).not.toHaveBeenCalled();
    expect(api.listPermissions).not.toHaveBeenCalled();
  });
});

describe("namespacing", () => {
  const guards = () => {
    const { user } = perimeter.validation(CONTEXT);
    if (!user) throw new Error("expected a user namespace guard");
    return user;
  };

  it("accepts an agentic identity in the request's project", async () => {
    await expect(guards().userIsNamespacedById(GRANTEE)).resolves.toBe(true);
    await expect(guards().userIsNamespacedByBody(GRANTEE)).resolves.toBe(true);
  });

  // The escalation this exists for: identifyUser falls back to the requestor's
  // own email, which a Drive ACL would happily accept.
  it("refuses a human address on both guards", async () => {
    await expect(guards().userIsNamespacedById(HUMAN)).resolves.toBe(false);
    await expect(guards().userIsNamespacedByBody(HUMAN)).resolves.toBe(false);
  });

  it("refuses an agentic identity from another project", async () => {
    const elsewhere = GRANTEE.replace(PROJECT_ID, "some-other-project");

    await expect(guards().userIsNamespacedById(elsewhere)).resolves.toBe(false);
  });
});
