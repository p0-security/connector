import { ConnectorError, createLogger } from "@p0security/connector-core";

import type { AccessTokenRequest, GithubClientContext } from "./context.ts";
import {
  type Repository,
  createAccessToken,
  listRepositories,
} from "./github-api.ts";
import { getSoleInstallationId } from "./installations.ts";
import { createAppJwt } from "./jwt.ts";

const logger = createLogger();

// GitHub's maximum page size for paginated list endpoints.
const REPOSITORIES_PER_PAGE = 100;

/** Makes a 422 from the token API a `validation_error` that names the
 * repository and permissions; P0 shows its message to the requestor. Returns
 * other errors unchanged. */
const toInstallationScopeError = (
  error: unknown,
  { repository, permissions }: AccessTokenRequest
): unknown => {
  if (!(error instanceof ConnectorError) || error.data.payload.status !== 422)
    return error;

  // GitHub sends 422 when the installation does not have a requested
  // permission or cannot access the repository. Its message does not tell
  // which, so the message names everything that was requested.
  const requested = Object.entries(permissions)
    .map(([permission, level]) => `${permission}:${level}`)
    .join(", ");
  const reason = String(error.data.payload.githubMessage ?? "").replace(
    /\.$/,
    ""
  );
  return new ConnectorError({
    type: "validation_error",
    message: `GitHub did not give a token for ${repository} with ${requested}${
      reason ? ` (${reason})` : ""
    }. Make sure that the GitHub App has these permissions, that the organization approved them, and that the App can access ${repository}.`,
    payload: { status: 422, repository, permissions: requested },
    cause: error,
  });
};

export const githubClientFor = async (context: GithubClientContext) => {
  const { privateKey, appId } = context;

  /** Signs a fresh App JWT from the shared identity and exchanges it for a scoped installation access token. */
  const mintInstallationAccessToken = async (
    request: AccessTokenRequest
  ): Promise<string> => {
    const { repository, permissions } = request;
    const auth = createAppJwt({ appId, privateKey });
    const installationId = await getSoleInstallationId(auth);

    const { token } = await createAccessToken({
      auth,
      installationId,
      repositories: [repository],
      permissions,
    }).catch((error: unknown) => {
      throw toInstallationScopeError(error, request);
    });

    logger.debug(
      { appId, installationId, repository, permissions },
      "minted installation access token"
    );
    return token;
  };

  /** Mints an installation token scoped to every repo the App can see, then walks `/installation/repositories` page by page until `total_count` repos have been collected. */
  const listAllRepositories = async (): Promise<Repository[]> => {
    const jwtAuth = createAppJwt({ appId, privateKey });
    const installationId = await getSoleInstallationId(jwtAuth);

    const { token } = await createAccessToken({
      auth: jwtAuth,
      installationId,
      // No permissions required. See
      // https://docs.github.com/en/rest/apps/installations?apiVersion=2026-03-10#list-repositories-accessible-to-the-app-installation
      permissions: {},
    });

    const installTokenAuth = { token };
    const repositories: Repository[] = [];
    let page = 1;
    while (true) {
      const data = await listRepositories({
        auth: installTokenAuth,
        page,
        per_page: REPOSITORIES_PER_PAGE,
      });
      repositories.push(...data.repositories);
      logger.debug(
        {
          appId,
          installationId,
          page,
          fetched: data.repositories.length,
          total: data.total,
        },
        "fetched a page of installation repositories"
      );
      if (data.repositories.length === 0 || repositories.length >= data.total)
        break;
      page++;
    }

    return repositories;
  };

  return {
    mintInstallationAccessToken,
    listAllRepositories,
  };
};
