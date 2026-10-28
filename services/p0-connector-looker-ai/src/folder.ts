import { ConnectorError } from "@p0security/connector-core";

import {
  type LookerSession,
  createContentAccess,
  deleteContentAccess,
  findFolder,
  listContentAccess,
  updateContentAccess,
} from "./looker/looker-api.ts";

/**
 * Gives a Looker service account edit access on the agent content folder, or
 * takes away the access it has there.
 *
 * Only the account's own access records change. What it can do there through
 * its groups, such as All Users, stays (W6).
 *
 * @param access `edit`, or `undefined` for none
 * @throws {ConnectorError} `object_not_found` when the folder doesn't exist
 *   and the account should have edit access on it
 */
export const setFolderAccess = async (
  session: LookerSession,
  grant: { folderId: string; userId: string; access: "edit" | undefined }
) => {
  const { folderId, userId, access } = grant;
  const folder = await findFolder(session, folderId);
  if (folder === undefined) {
    // Nothing to take away.
    if (access === undefined) return;
    throw new ConnectorError({
      type: "object_not_found",
      message: `The Looker folder ${folderId}, which P0 was set up to give edit grants access to, doesn't exist. Pick another folder in P0's Looker integration settings.`,
      payload: { folderId },
    });
  }

  const own = (
    await listContentAccess(session, folder.contentMetadataId)
  ).filter((record) => record.userId === userId);

  if (access === undefined) {
    for (const record of own) await deleteContentAccess(session, record.id);
    return;
  }

  if (own.some((record) => record.permissionType === "edit")) return;
  const [first] = own;
  if (first !== undefined) {
    await updateContentAccess(session, first.id, "edit");
    return;
  }
  await createContentAccess(session, {
    contentMetadataId: folder.contentMetadataId,
    userId,
    permissionType: "edit",
  });
};
