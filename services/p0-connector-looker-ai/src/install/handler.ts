import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
} from "@p0security/connector";

import { withInstance } from "../instance.ts";
import {
  type LookerSession,
  findFolder,
  listGroupsWithRoles,
  listModels,
  listPermissionParents,
} from "../looker/looker-api.ts";
import {
  LEVEL_PERMISSIONS,
  REFUSED_PERMISSIONS,
  closeOverParents,
} from "../roles.ts";
import { type InstallValidation, installContext } from "./definition.ts";

const toUnique = (items: string[]) => [...new Set(items)].sort();

/**
 * Runs the install checks and reports each one separately, so P0 can say
 * exactly what to fix. The caller has already signed in with the Admin key,
 * which every check needs.
 */
export const fetchInstallValidation = async (
  looker: LookerSession,
  contentFolderId: string | undefined
): Promise<InstallValidation> => {
  const models = await listModels(looker);

  const parents = await listPermissionParents(looker);
  const levels = Object.values(LEVEL_PERMISSIONS).map((wanted) =>
    closeOverParents(wanted, parents)
  );

  const groups = await listGroupsWithRoles(looker);

  return {
    adminKeyAccepted: true,
    models: models.length,
    missingPermissions: toUnique(levels.flatMap(({ missing }) => missing)),
    refusedPermissions: toUnique(
      levels.flatMap(({ permissions }) =>
        permissions.filter((permission) => REFUSED_PERMISSIONS.has(permission))
      )
    ),
    inheritedRoles: groups
      .filter((group) => group.includeByDefault && group.roles.length > 0)
      .map((group) => ({ group: group.name, roles: group.roles })),
    contentFolderFound:
      contentFolderId === undefined
        ? null
        : (await findFolder(looker, contentFolderId)) !== undefined,
  };
};

const ADMIN_KEY_REJECTED: InstallValidation = {
  adminKeyAccepted: false,
  models: 0,
  missingPermissions: [],
  refusedPermissions: [],
  inheritedRoles: [],
  contentFolderFound: null,
};

const isAdminKeyRejected = (error: unknown) =>
  error instanceof ConnectorError &&
  error.data.payload.reason === "admin_key_rejected";

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router, procedure } = t;

  return router({
    get: procedure.input(installContext.parse).query(async ({ input, ctx }) => {
      const logger = ctx.logger.child({ baseUrl: input.baseUrl });
      const validation = await withInstance(logger, input, ({ looker }) =>
        fetchInstallValidation(looker, input.contentFolderId)
      ).catch((error: unknown) => {
        if (isAdminKeyRejected(error)) return ADMIN_KEY_REJECTED;
        throw error;
      });
      logger.info(validation, "validated the Looker install");
      return validation;
    }),
  });
};
