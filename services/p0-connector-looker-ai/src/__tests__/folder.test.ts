import { ConnectorError } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { setFolderAccess } from "../folder.ts";
import * as api from "../looker/looker-api.ts";

vi.mock("../looker/looker-api.ts");

const SESSION = { baseUrl: "https://example.looker.app", accessToken: "t" };
const FOLDER = "42";
const ACCOUNT = "100";

/** The folder's access records. */
let records: api.LookerContentAccess[];
let nextId: number;
const changes: string[] = [];

beforeEach(() => {
  vi.resetAllMocks();
  nextId = 1;
  changes.length = 0;
  records = [{ id: "group-1", userId: undefined, permissionType: "edit" }];

  vi.mocked(api.findFolder).mockResolvedValue({ contentMetadataId: "cm-7" });
  vi.mocked(api.listContentAccess).mockImplementation(async () => [...records]);
  vi.mocked(api.createContentAccess).mockImplementation(async (_, access) => {
    records.push({
      id: String(nextId++),
      userId: access.userId,
      permissionType: access.permissionType,
    });
    changes.push(`create ${access.contentMetadataId} ${access.permissionType}`);
  });
  vi.mocked(api.updateContentAccess).mockImplementation(async (_, id, type) => {
    const record = records.find((r) => r.id === id);
    if (record) record.permissionType = type;
    changes.push(`update ${id} ${type}`);
  });
  vi.mocked(api.deleteContentAccess).mockImplementation(async (_, id) => {
    records = records.filter((r) => r.id !== id);
    changes.push(`delete ${id}`);
  });
});

const giveEdit = () =>
  setFolderAccess(SESSION, {
    folderId: FOLDER,
    userId: ACCOUNT,
    access: "edit",
  });
const takeAway = () =>
  setFolderAccess(SESSION, {
    folderId: FOLDER,
    userId: ACCOUNT,
    access: undefined,
  });

const own = () => records.filter((r) => r.userId === ACCOUNT);

describe("setFolderAccess", () => {
  it("gives the account edit access on the folder", async () => {
    await giveEdit();

    expect(api.findFolder).toHaveBeenCalledWith(SESSION, FOLDER);
    expect(changes).toEqual(["create cm-7 edit"]);
    expect(own()).toEqual([
      { id: "1", userId: ACCOUNT, permissionType: "edit" },
    ]);
  });

  it("is idempotent", async () => {
    await giveEdit();
    await giveEdit();

    expect(changes).toEqual(["create cm-7 edit"]);
  });

  it("raises a view record to edit, instead of adding another", async () => {
    records.push({ id: "5", userId: ACCOUNT, permissionType: "view" });

    await giveEdit();

    expect(changes).toEqual(["update 5 edit"]);
    expect(own()).toEqual([
      { id: "5", userId: ACCOUNT, permissionType: "edit" },
    ]);
  });

  it("leaves other users' and groups' records alone", async () => {
    records.push({ id: "6", userId: "200", permissionType: "view" });

    await giveEdit();
    await takeAway();

    expect(records).toEqual([
      { id: "group-1", userId: undefined, permissionType: "edit" },
      { id: "6", userId: "200", permissionType: "view" },
    ]);
  });

  it("takes away every record the account has", async () => {
    records.push(
      { id: "5", userId: ACCOUNT, permissionType: "view" },
      { id: "8", userId: ACCOUNT, permissionType: "edit" }
    );

    await takeAway();

    expect(changes).toEqual(["delete 5", "delete 8"]);
    expect(own()).toEqual([]);
  });

  it("fails an edit grant when the folder doesn't exist", async () => {
    vi.mocked(api.findFolder).mockResolvedValue(undefined);

    const error = await giveEdit().catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data).toEqual({
      type: "object_not_found",
      message:
        "The Looker folder 42, which P0 was set up to give edit grants access to, doesn't exist. Pick another folder in P0's Looker integration settings.",
      payload: { folderId: FOLDER },
    });
    expect(changes).toEqual([]);
  });

  it("has nothing to take away when the folder doesn't exist", async () => {
    vi.mocked(api.findFolder).mockResolvedValue(undefined);

    await expect(takeAway()).resolves.toBeUndefined();
    expect(api.listContentAccess).not.toHaveBeenCalled();
  });
});
