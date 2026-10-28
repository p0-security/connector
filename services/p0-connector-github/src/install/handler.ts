import type { AnyConnectorTRPCInstance } from "@p0security/connector";

import { appCredentials } from "../accesses/common/definition.ts";
import {
  type GitHubClient,
  REQUIRED_PERMISSIONS,
  connectGitHub,
  missingPermissions,
} from "../github/client.ts";
import { AppNotInstalledError, callGitHub } from "../github/errors.ts";
import type { InstallValidation } from "./definition.ts";

// What the `role` access needs on its own. An installation missing a
// permission is reported at this level too, so P0 can tell an app with no
// Members permission, which the `role` access can't work without, from one
// with Members: read, which only the `team` access needs raised.
const ROLE_PERMISSIONS = { ...REQUIRED_PERMISSIONS, members: "read" } as const;

/**
 * The install checks, each reported separately so P0 can say exactly what to
 * fix: the key works, the app is installed on the org and not suspended, and
 * the installation holds every permission the connector asks for.
 */
export const fetchInstallValidation = async (
  github: Pick<GitHubClient, "fetchInstallation" | "verifyAppJwt">
): Promise<InstallValidation> => {
  if (!(await github.verifyAppJwt())) {
    return {
      keyAccepted: false,
      installed: false,
      suspended: false,
      missingPermissions: [],
      repositorySelection: null,
    };
  }

  const installation = await github.fetchInstallation().catch((error) => {
    if (error instanceof AppNotInstalledError) return null;
    throw error;
  });
  if (!installation) {
    return {
      keyAccepted: true,
      installed: false,
      suspended: false,
      missingPermissions: [],
      repositorySelection: null,
    };
  }

  return {
    keyAccepted: true,
    installed: true,
    suspended: installation.suspended,
    missingPermissions: [
      ...new Set([
        ...missingPermissions(installation.permissions, ROLE_PERMISSIONS),
        ...missingPermissions(installation.permissions, REQUIRED_PERMISSIONS),
      ]),
    ].sort(),
    repositorySelection: installation.repositorySelection,
  };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router, procedure } = t;

  return router({
    get: procedure.input(appCredentials.parse).query(async ({ input, ctx }) => {
      const { org, appId } = input;
      const logger = ctx.logger.child({ org, appId });
      const github = await connectGitHub(input);
      const validation = await callGitHub(
        () => fetchInstallValidation(github),
        { org }
      );
      logger.info(validation, "validated the GitHub App installation");
      return validation;
    }),
  });
};
