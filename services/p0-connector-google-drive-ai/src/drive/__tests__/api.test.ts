import type { drive_v3 } from "@googleapis/drive";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { newDriveApi } from "../api.ts";

const FILE_ID = "1XyZ_folder_id";

const newClient = () => ({
  files: {
    get: vi.fn().mockResolvedValue({
      data: {
        id: FILE_ID,
        name: "Quarterly reports",
        mimeType: "application/vnd.google-apps.folder",
        driveId: "0ABCdefGHIjklUk9PVA",
      },
    }),
    list: vi.fn().mockResolvedValue({ data: { files: [] } }),
  },
  permissions: {
    list: vi.fn().mockResolvedValue({ data: { permissions: [] } }),
    create: vi.fn().mockResolvedValue({ data: {} }),
    update: vi.fn().mockResolvedValue({ data: {} }),
    delete: vi.fn().mockResolvedValue({ data: {} }),
  },
});

let client: ReturnType<typeof newClient>;
let api: ReturnType<typeof newDriveApi>;

beforeEach(() => {
  client = newClient();
  api = newDriveApi(client as unknown as drive_v3.Drive);
});

describe("getFile", () => {
  it("asks for only the fields the perimeter reads, across all drives", async () => {
    await api.getFile(FILE_ID);

    expect(client.files.get).toHaveBeenCalledWith({
      fileId: FILE_ID,
      fields: "id,name,mimeType,driveId",
      supportsAllDrives: true,
    });
  });

  it("answers undefined on a 404 rather than throwing", async () => {
    client.files.get.mockRejectedValue(
      Object.assign(new Error("nope"), { code: 404 })
    );

    await expect(api.getFile(FILE_ID)).resolves.toBeUndefined();
  });

  it("lets any other failure propagate", async () => {
    client.files.get.mockRejectedValue(
      Object.assign(new Error("nope"), { code: 403 })
    );

    await expect(api.getFile(FILE_ID)).rejects.toThrow("nope");
  });
});

describe("listFiles", () => {
  const DRIVE_ID = "0ABCdefGHIjklUk9PVA";

  it("asks for one drive's untrashed items, across all drives", async () => {
    await api.listFiles(DRIVE_ID);

    expect(client.files.list).toHaveBeenCalledWith({
      corpora: "drive",
      driveId: DRIVE_ID,
      fields: "nextPageToken,files(id,name,mimeType,driveId)",
      includeItemsFromAllDrives: true,
      pageSize: 1000,
      pageToken: undefined,
      q: "trashed = false",
      supportsAllDrives: true,
    });
  });

  it("pages to the end, dropping items without an id or name", async () => {
    client.files.list
      .mockResolvedValueOnce({
        data: {
          files: [
            { id: FILE_ID, name: "Quarterly reports", driveId: DRIVE_ID },
          ],
          nextPageToken: "page-2",
        },
      })
      .mockResolvedValueOnce({ data: { files: [{ id: "1noName" }] } });

    await expect(api.listFiles(DRIVE_ID)).resolves.toEqual([
      {
        id: FILE_ID,
        name: "Quarterly reports",
        mimeType: "",
        driveId: DRIVE_ID,
      },
    ]);
    expect(client.files.list).toHaveBeenLastCalledWith(
      expect.objectContaining({ pageToken: "page-2" })
    );
  });
});

describe("listPermissions", () => {
  // An item can hold far more entries than one page; a missed entry would read
  // as "create" and Drive would then refuse the duplicate.
  it("pages to the end", async () => {
    client.permissions.list
      .mockResolvedValueOnce({
        data: {
          permissions: [{ id: "p1", role: "reader", emailAddress: "a@b.com" }],
          nextPageToken: "page-2",
        },
      })
      .mockResolvedValueOnce({
        data: { permissions: [{ id: "p2", role: "writer" }] },
      });

    await expect(api.listPermissions(FILE_ID)).resolves.toEqual([
      { id: "p1", role: "reader", emailAddress: "a@b.com" },
      { id: "p2", role: "writer", emailAddress: undefined },
    ]);
    expect(client.permissions.list).toHaveBeenCalledTimes(2);
  });
});

describe("createPermission", () => {
  it("writes one user entry and sends no notification", async () => {
    await api.createPermission(
      FILE_ID,
      "p0a-1@proj.iam.gserviceaccount.com",
      "writer"
    );

    expect(client.permissions.create).toHaveBeenCalledWith({
      fileId: FILE_ID,
      supportsAllDrives: true,
      sendNotificationEmail: false,
      requestBody: {
        type: "user",
        emailAddress: "p0a-1@proj.iam.gserviceaccount.com",
        role: "writer",
      },
    });
  });
});
