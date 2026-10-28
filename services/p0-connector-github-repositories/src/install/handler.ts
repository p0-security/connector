import type { AnyConnectorTRPCInstance } from "@p0security/connector";

import { appCredentials } from "../accesses/role/definition.ts";
import {
  type GitHubClient,
  REQUIRED_PERMISSIONS,
  connectGitHub,
  missingPermissions,
} from "../github/client.ts";
import { AppNotInstalledError, callGitHub } from "../github/errors.ts";
import type { InstallValidation } from "./definition.ts";

/**
 * The install checks, each reported separately so P0 can say exactly what to
 * fix: the key works, the app is installed on the org and not suspended, and
 * the installation holds every permission the connector asks for.
 */
export const getInstallValidation = async (
  github: Pick<GitHubClient, "findInstallation" | "isAppJwtAccepted">
): Promise<InstallValidation> => {
  if (!(await github.isAppJwtAccepted())) {
    return {
      keyAccepted: false,
      installed: false,
      suspended: false,
      missingPermissions: [],
      repositorySelection: null,
    };
  }

  const installation = await github.findInstallation().catch((error) => {
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
    missingPermissions: missingPermissions(
      installation.permissions,
      REQUIRED_PERMISSIONS
    ),
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
      const validation = await callGitHub(() => getInstallValidation(github), {
        org,
      });
      logger.info(validation, "validated the GitHub App installation");
      return validation;
    }),
  });
};
