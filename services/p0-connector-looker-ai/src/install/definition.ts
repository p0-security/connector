import { z } from "zod";

import {
  contentFolderId,
  instanceContext,
} from "../accesses/model/definition.ts";

/** What the install check reads: the instance, where its Admin key is, and
 * the agent content folder, if the customer picked one. */
export const installContext = instanceContext.extend({
  contentFolderId: contentFolderId.optional(),
});

export const installValidation = z.object({
  /** Looker accepted the Admin key at the instance's URL. When `false`, every
   * other check is empty. */
  adminKeyAccepted: z.boolean(),
  /** How many models a grant can name: those with an Explore, that aren't
   * hidden. */
  models: z.number().int().nonnegative(),
  /** Permissions a level needs that the instance doesn't list. A grant at that
   * level fails until it does. */
  missingPermissions: z.array(z.string()),
  /** Permissions P0 never grants that a level would hold on this instance,
   * as parents of the ones it asks for. A grant at that level fails. */
  refusedPermissions: z.array(z.string()),
  /** Groups that a new Looker service account joins, and their roles. Every
   * grant's account holds these roles as well as P0's, and P0 can't take them
   * away (W2, W6). */
  inheritedRoles: z.array(
    z.object({ group: z.string(), roles: z.array(z.string()) })
  ),
  /** Whether the agent content folder exists, or `null` when none was
   * picked. */
  contentFolderFound: z.boolean().nullable(),
});
export type InstallValidation = z.infer<typeof installValidation>;
