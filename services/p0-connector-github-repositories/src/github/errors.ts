import {
  ConnectorError,
  type ConnectorErrorType,
  connectorErrorTypeForHttpStatus,
} from "@p0security/connector-core";

import { GitHubError } from "./api.ts";

/**
 * The installation can't see the repository: the customer removed it from the
 * app's repository selection, or it no longer exists.
 *
 * GitHub refuses to mint a token for it, so this is detected before anything
 * is read or written.
 */
export class RepositoryNotVisibleError extends Error {
  constructor(readonly repo: string) {
    super(`Repository ${repo} isn't visible to the GitHub App installation`);
    this.name = "RepositoryNotVisibleError";
  }
}

/** The app isn't installed on the org (or there's no such org): `GET /orgs/{org}/installation` answered 404. */
export class AppNotInstalledError extends Error {
  constructor() {
    super("The GitHub App isn't installed on the org");
    this.name = "AppNotInstalledError";
  }
}

/** An org owner suspended the app's installation, so GitHub won't mint tokens for it. */
export class InstallationSuspendedError extends Error {
  constructor() {
    super("The GitHub App installation is suspended");
    this.name = "InstallationSuspendedError";
  }
}

/** The installation wasn't granted a permission a token was about to ask for. */
export class MissingPermissionsError extends Error {
  constructor(readonly permissions: string[]) {
    super(`The installation is missing ${permissions.join(", ")}`);
    this.name = "MissingPermissionsError";
  }
}

/** Where a GitHub call was aimed, for the messages a failure turns into. */
export type GitHubTarget = {
  org: string;
  repo?: string;
  login?: string;
  /**
   * The call was changing a role (a grant or a revoke), not reading at request
   * time. A repo that left the app's selection then needs someone to step in,
   * where a read only needs the repo added.
   */
  changingRole?: boolean;
};

const repositoryNotVisible = (
  { org, login, changingRole }: GitHubTarget,
  repo: string
) =>
  new ConnectorError({
    type: "object_not_found",
    message: changingRole
      ? `${repo} isn't in the GitHub App's repository selection, so P0 couldn't change ${
          login ?? "the user"
        }'s role. Add the repo back to the app and retry, or change the role in GitHub.`
      : `${repo} isn't in the GitHub App's repository selection. Ask your GitHub admin to add it to the app.`,
    // `query` is the field P0 reads off an `object_not_found`.
    payload: { query: `${org}/${repo}`, org, repo },
  });

const missingPermission = (org: string, permission: string | undefined) =>
  new ConnectorError({
    type: "insufficient_privileges",
    message: `The GitHub App for ${org} is missing ${
      permission ?? "a permission this call needs"
    }. Grant it in the app's settings and accept the update on the installation.`,
    payload: { org, ...(permission ? { permission } : {}) },
  });

/** GitHub's secondary rate limits arrive as a 403, so a 403 alone doesn't mean a missing permission. */
const isRateLimit = (error: GitHubError) =>
  error.githubMessages.some((message) => /rate limit/i.test(message));

/** Nor does a suspended installation's: "This installation has been suspended". */
const isSuspended = (error: GitHubError) =>
  error.status === 403 &&
  error.githubMessages.some((message) =>
    /installation has been suspended/i.test(message)
  );

const installationSuspended = (org: string) =>
  new ConnectorError({
    type: "insufficient_privileges",
    message: `The GitHub App's installation on ${org} is suspended. Ask an owner of ${org} to unsuspend it in the org's GitHub App settings, then retry.`,
    payload: { reason: "installation_suspended", org },
  });

const notInstalled = (org: string) =>
  new ConnectorError({
    type: "insufficient_privileges",
    message: `The GitHub App isn't installed on ${org}. Install it on the org, or check the org name in the P0 install, then retry.`,
    payload: { reason: "not_installed", org },
  });

/** A 401 means GitHub didn't accept the App JWT: wrong key for the app id, a revoked key, or a skewed clock. */
const credentialsRejected = (org: string) =>
  new ConnectorError({
    type: "insufficient_privileges",
    message: `GitHub rejected the GitHub App credentials for ${org}. Check that the app ID and the private key in the connector's secret manager belong to the same app, that the key hasn't been revoked, and that the connector's clock is accurate.`,
    payload: { reason: "credentials_rejected", org },
  });

const typeForStatus = (error: GitHubError): ConnectorErrorType => {
  if (error.status === undefined) return "upstream_unavailable";
  if (error.status === 403 && isRateLimit(error)) return "rate_limited";
  return connectorErrorTypeForHttpStatus(error.status);
};

const notFoundSubject = ({ org, repo, login }: GitHubTarget) => {
  if (repo && login) return `${login} or ${repo} in ${org}`;
  if (repo ?? login) return `${repo ?? login} in ${org}`;
  return org;
};

/**
 * The message P0 shows for a GitHub failure with no more specific mapping.
 *
 * Fixed per type, because P0 posts it to requesters and approver channels:
 * {@link GitHubError}'s own message names the method and path, which can carry
 * the installation id, org, repo, login or invitation id. That text is logged
 * (at `warn`, by the request helpers) and goes no further. Only `unknown`
 * quotes GitHub, since GitHub's words are all there is to go on, and never the
 * path.
 */
const messageFor = (
  type: ConnectorErrorType,
  error: GitHubError,
  target: GitHubTarget
): string => {
  const { org } = target;
  switch (type) {
    case "upstream_unavailable":
      return error.status === undefined
        ? "The connector couldn't reach GitHub. Check that it can reach api.github.com, then retry."
        : "GitHub couldn't answer the connector's request right now. Retry in a few minutes, and check githubstatus.com if it keeps failing.";
    case "rate_limited":
      return `GitHub is rate limiting the GitHub App for ${org}. Retry in a few minutes.`;
    case "object_not_found":
      return `GitHub couldn't find ${notFoundSubject(target)}. Check that it still exists, and that the GitHub App is still installed on ${org}.`;
    default:
      return `GitHub refused the connector's request for ${org}${
        error.status === undefined ? "" : ` (${error.status})`
      }: ${error.githubMessages.join("; ")}`;
  }
};

/**
 * Maps a failed GitHub call onto the {@link ConnectorError} P0 surfaces.
 *
 * Anything that isn't a GitHub failure is returned as is, so a bug stays a bug
 * rather than being dressed up as an upstream error.
 */
export const toConnectorError = (
  error: unknown,
  target: GitHubTarget
): unknown => {
  const { org, repo } = target;
  if (error instanceof ConnectorError) return error;

  if (error instanceof RepositoryNotVisibleError) {
    return repositoryNotVisible(target, error.repo);
  }

  if (error instanceof AppNotInstalledError) return notInstalled(org);

  if (error instanceof InstallationSuspendedError) {
    return installationSuspended(org);
  }

  if (error instanceof MissingPermissionsError) {
    return missingPermission(org, error.permissions.join(", "));
  }

  if (error instanceof GitHubError) {
    if (isSuspended(error)) return installationSuspended(org);
    if (error.status === 401) return credentialsRejected(org);
    const type = typeForStatus(error);
    if (type === "insufficient_privileges") {
      return missingPermission(org, error.acceptedPermissions);
    }
    return new ConnectorError({
      type,
      message: messageFor(type, error, target),
      payload: {
        org,
        ...(repo ? { repo } : {}),
        ...(error.status !== undefined ? { status: error.status } : {}),
      },
    });
  }

  return error;
};

/** Runs GitHub calls, mapping any failure through {@link toConnectorError}. */
export const callGitHub = async <T>(
  fn: () => Promise<T>,
  target: GitHubTarget
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    throw toConnectorError(error, target);
  }
};
