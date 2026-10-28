import type { drive_v3 } from "@googleapis/drive";

import { statusOf } from "./errors.ts";

/** The roles this perimeter is willing to put on a Drive ACL. */
type DriveRole = "reader" | "writer";

/** A Drive item, reduced to the fields this connector reads. */
export type DriveFile = {
  id: string;
  name: string;
  mimeType: string;
  /** The shared drive holding the item; absent for an item in a My Drive. */
  driveId: string | undefined;
};

/** One entry on a Drive item's ACL. */
export type DrivePermission = {
  id: string;
  /** Drive's own role string, which may be one this connector cannot set. */
  role: string;
  /** Present for `type: "user"` entries, which is all this connector writes. */
  emailAddress: string | undefined;
};

/**
 * The slice of Drive v3 this connector uses, as an interface so the perimeter's
 * primitives can be exercised without googleapis in the way.
 *
 * Every method runs as the connector's own service identity — see
 * {@link newDriveClient}.
 */
export type DriveApi = {
  /** Resolves one item. `undefined` on 404, which Drive answers both for an
   * item that does not exist and for one in a drive this connector cannot see. */
  getFile: (fileId: string) => Promise<DriveFile | undefined>;
  /** Every non-trashed item in a shared drive, at any depth, across pages. */
  listFiles: (driveId: string) => Promise<DriveFile[]>;
  /** Every ACL entry on an item, across pages. */
  listPermissions: (fileId: string) => Promise<DrivePermission[]>;
  createPermission: (
    fileId: string,
    emailAddress: string,
    role: DriveRole
  ) => Promise<void>;
  updatePermission: (
    fileId: string,
    permissionId: string,
    role: DriveRole
  ) => Promise<void>;
  deletePermission: (fileId: string, permissionId: string) => Promise<void>;
};

const FILE_FIELDS = "id,name,mimeType,driveId";
const LIST_FIELDS = `nextPageToken,files(${FILE_FIELDS})`;
const PERMISSION_FIELDS = "nextPageToken,permissions(id,emailAddress,role)";

// Drive's maximum for `permissions.list`; an item can carry far more entries
// than one page, so the list is paged to the end rather than truncated —
// a missed entry would read as "create" and Drive would refuse the duplicate.
const PERMISSION_PAGE_SIZE = 100;

// Drive's maximum for `files.list`.
const FILE_PAGE_SIZE = 1000;

/** Drive's generated schema types every field as nullable. An item with no id
 * or name is not one this connector can resolve or act on. */
const toDriveFile = (data: drive_v3.Schema$File): DriveFile | undefined =>
  data.id && data.name
    ? {
        id: data.id,
        name: data.name,
        mimeType: data.mimeType ?? "",
        driveId: data.driveId ?? undefined,
      }
    : undefined;

/** Binds {@link DriveApi} to a Drive v3 client. */
export const newDriveApi = (client: drive_v3.Drive): DriveApi => ({
  getFile: async (fileId) => {
    try {
      const { data } = await client.files.get({
        fileId,
        fields: FILE_FIELDS,
        supportsAllDrives: true,
      });
      return toDriveFile(data);
    } catch (error) {
      if (statusOf(error) === 404) return undefined;
      throw error;
    }
  },

  listFiles: async (driveId) => {
    const files: DriveFile[] = [];
    let pageToken: string | undefined;
    do {
      const { data } = await client.files.list({
        corpora: "drive",
        driveId,
        fields: LIST_FIELDS,
        includeItemsFromAllDrives: true,
        pageSize: FILE_PAGE_SIZE,
        pageToken,
        q: "trashed = false",
        supportsAllDrives: true,
      });
      for (const file of data.files ?? []) {
        const driveFile = toDriveFile(file);
        if (driveFile) files.push(driveFile);
      }
      pageToken = data.nextPageToken ?? undefined;
    } while (pageToken);
    return files;
  },

  listPermissions: async (fileId) => {
    const permissions: DrivePermission[] = [];
    let pageToken: string | undefined;
    do {
      const { data } = await client.permissions.list({
        fileId,
        fields: PERMISSION_FIELDS,
        supportsAllDrives: true,
        pageSize: PERMISSION_PAGE_SIZE,
        pageToken,
      });
      for (const permission of data.permissions ?? []) {
        if (!permission.id || !permission.role) continue;
        permissions.push({
          id: permission.id,
          role: permission.role,
          emailAddress: permission.emailAddress ?? undefined,
        });
      }
      pageToken = data.nextPageToken ?? undefined;
    } while (pageToken);
    return permissions;
  },

  createPermission: async (fileId, emailAddress, role) => {
    await client.permissions.create({
      fileId,
      supportsAllDrives: true,
      // The grantee is a service account, which has no mailbox; and a
      // just-in-time grant is not something to announce by email in any case.
      sendNotificationEmail: false,
      requestBody: { type: "user", emailAddress, role },
    });
  },

  updatePermission: async (fileId, permissionId, role) => {
    await client.permissions.update({
      fileId,
      permissionId,
      supportsAllDrives: true,
      requestBody: { role },
    });
  },

  deletePermission: async (fileId, permissionId) => {
    await client.permissions.delete({
      fileId,
      permissionId,
      supportsAllDrives: true,
    });
  },
});
