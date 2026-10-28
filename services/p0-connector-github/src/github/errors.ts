import {
  ConnectorError,
  type ConnectorErrorType,
  connectorErrorTypeForHttpStatus,
  throwAssertNever,
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

/** The org has no team with this id any more: ids aren't reused, so it was deleted. */
export class TeamNotFoundError extends Error {
  constructor(readonly teamId: string) {
    super(`The team with id ${teamId} doesn't exist in the org`);
    this.name = "TeamNotFoundError";
  }
}

/**
 * GitHub refused a change to who is on a team, with a 403 that nothing else
 * explains ({@link isUnexplainedRefusal}). It documents one for a team that's
 * synced with an identity provider group, but not its wording, so GitHub's own
 * messages are kept to show.
 */
export class TeamChangeRefusedError extends Error {
  constructor(readonly githubMessages: string[]) {
    super("GitHub refused to change the team's members");
    this.name = "TeamChangeRefusedError";
  }
}

/** A branch, by its repository and name. */
type Branch = { repo: string; branch: string };

/** GitHub has no protection for the branch: it answered 404, which it also does when there's no such branch. */
export class BranchNotProtectedError extends Error {
  constructor(readonly target: Branch) {
    super(`${target.repo}'s ${target.branch} branch isn't protected`);
    this.name = "BranchNotProtectedError";
  }
}

/** The branch's protection doesn't require pull request reviews, so it has no bypass list. */
export class ReviewsNotRequiredError extends Error {
  constructor(readonly target: Branch) {
    super(
      `${target.repo}'s ${target.branch} branch doesn't require pull request reviews`
    );
    this.name = "ReviewsNotRequiredError";
  }
}

/**
 * No protection rule names the branch exactly, so the protection it has comes
 * from a wildcard rule. Changing that rule's bypass list would change it for
 * every branch the pattern matches.
 */
export class WildcardRuleError extends Error {
  constructor(readonly target: Branch) {
    super(
      `${target.repo}'s ${target.branch} branch is protected by a wildcard rule only`
    );
    this.name = "WildcardRuleError";
  }
}

/**
 * GitHub refused a change to a branch's bypass list with a 422: the user has
 * no write access to the repository, or the list is full. GitHub's own
 * messages are kept to show.
 */
export class BypassChangeRefusedError extends Error {
  constructor(
    readonly target: Branch,
    readonly githubMessages: string[]
  ) {
    super("GitHub refused to change the branch's bypass list");
    this.name = "BypassChangeRefusedError";
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

/** What a GitHub call was aimed at in the org: a repository, a team by its slug, or neither. */
type TargetResource =
  | { repo: string; team?: never }
  | { repo?: never; team?: never }
  | { team: string; repo?: never };

/** Where a GitHub call was aimed, for the messages a failure turns into. */
export type GitHubTarget = TargetResource & {
  org: string;
  login?: string;
  /**
   * The call was changing the user's access (a grant or a revoke), not reading
   * at request time. A repo that left the app's selection, or a team that's
   * gone, then needs someone to step in, where a read only needs the repo
   * added or another team picked.
   */
  changingAccess?: boolean;
};

const repositoryNotVisible = (
  { org, login, changingAccess }: GitHubTarget,
  repo: string
) =>
  new ConnectorError({
    type: "object_not_found",
    message: changingAccess
      ? `${repo} isn't in the GitHub App's repository selection, so P0 couldn't change ${
          login ?? "the user"
        }'s role. Add the repo back to the app and retry, or change the role in GitHub.`
      : `${repo} isn't in the GitHub App's repository selection. Ask your GitHub admin to add it to the app.`,
    // `query` is the field P0 reads off an `object_not_found`.
    payload: { query: `${org}/${repo}`, org, repo },
  });

const teamNotFound = (
  { org, login, changingAccess }: GitHubTarget,
  teamId: string
) =>
  new ConnectorError({
    type: "object_not_found",
    // Only a membership is refused for a team that's gone. Removing one
    // succeeds, since a deleted team has no members.
    message: changingAccess
      ? `The team with id ${teamId} doesn't exist in ${org} any more, so P0 couldn't add ${
          login ?? "the user"
        } to it. Request access to a team that does.`
      : `The team with id ${teamId} doesn't exist in ${org} any more. Request access to a team that does.`,
    // `query` is the field P0 reads off an `object_not_found`.
    payload: { query: `${org}/${teamId}`, org, teamId },
  });

// GitHub's words are quoted, since they're what an admin has to go on, and
// the sync is named as a possibility, not a diagnosis.
const teamChangeRefused = (
  { org, team, login }: GitHubTarget,
  githubMessages: string[]
) =>
  new ConnectorError({
    type: "validation_error",
    message: `GitHub refused to change who is on ${
      team ?? "the team"
    } (${githubMessages.join("; ")}). If the team is synced with an identity provider group, change its members in the identity provider.`,
    payload: {
      reason: "team_change_refused",
      org,
      ...(team ? { team } : {}),
      ...(login ? { login } : {}),
    },
  });

const branchNotProtected = (org: string, { repo, branch }: Branch) =>
  new ConnectorError({
    type: "validation_error",
    message: `${repo}'s ${branch} branch isn't protected, or doesn't exist. Force-merge access needs a branch protection rule for exactly ${branch} that requires pull request reviews.`,
    payload: { reason: "branch_not_protected", org, repo, branch },
  });

const reviewsNotRequired = (org: string, { repo, branch }: Branch) =>
  new ConnectorError({
    type: "validation_error",
    message: `${repo}'s ${branch} branch doesn't require pull request reviews, so there are none to bypass. Turn on "Require a pull request before merging" in the branch's protection rule.`,
    payload: { reason: "reviews_not_required", org, repo, branch },
  });

const wildcardRule = (org: string, { repo, branch }: Branch) =>
  new ConnectorError({
    type: "validation_error",
    message: `${repo}'s ${branch} branch is protected by a wildcard rule, which other branches can share, so P0 won't change who can bypass it. Ask a repo admin to add a branch protection rule for exactly ${branch}.`,
    payload: { reason: "wildcard_rule", org, repo, branch },
  });

// GitHub's words are quoted, since they're what an admin has to go on.
const bypassChangeRefused = (
  { org, login }: GitHubTarget,
  { repo, branch }: Branch,
  githubMessages: string[]
) =>
  new ConnectorError({
    type: "validation_error",
    message: `GitHub refused to change who can bypass reviews on ${repo}'s ${branch} branch (${githubMessages.join("; ")}). Check that ${
      login ?? "the user"
    } has write access to ${repo}, and that the bypass list has room: GitHub allows 100 users, teams and apps in all.`,
    payload: {
      reason: "bypass_change_refused",
      org,
      repo,
      branch,
      ...(login ? { login } : {}),
    },
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

/** A 403 from a suspended installation: "This installation has been suspended". */
const isSuspended = (error: GitHubError) =>
  error.status === 403 &&
  error.githubMessages.some((message) =>
    /installation has been suspended/i.test(message)
  );

/** A token that lacks the permission a call needs: "Resource not accessible by integration". */
const isMissingPermission = (error: GitHubError) =>
  error.githubMessages.some((message) =>
    /not accessible by integration/i.test(message)
  );

/**
 * A 403 from the org's IP allow list: "... the `acme`
 * organization has an IP allow list enabled, and your IP address is not
 * permitted to access this resource."
 */
const isIpNotAllowed = (error: GitHubError) =>
  error.status === 403 &&
  error.githubMessages.some((message) => /IP allow list/i.test(message));

/** A 403 that none of the 403s this file knows about explains. */
export const isUnexplainedRefusal = (error: unknown): error is GitHubError =>
  error instanceof GitHubError &&
  error.status === 403 &&
  !isRateLimit(error) &&
  !isSuspended(error) &&
  !isMissingPermission(error) &&
  !isIpNotAllowed(error);

const installationSuspended = (org: string) =>
  new ConnectorError({
    type: "insufficient_privileges",
    message: `The GitHub App's installation on ${org} is suspended. Ask an owner of ${org} to unsuspend it in the org's GitHub App settings, then retry.`,
    payload: { reason: "installation_suspended", org },
  });

const ipNotAllowed = (org: string) =>
  new ConnectorError({
    type: "insufficient_privileges",
    message: `${org}'s IP allow list doesn't include the connector's IP address, so GitHub refused the connector's request. Add the connector's outbound IP address to the org's allow list, then retry.`,
    payload: { reason: "ip_not_allowed", org },
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

const notFoundSubject = ({ org, repo, team, login }: GitHubTarget) => {
  const resource = repo ?? team;
  if (resource && login) return `${login} or ${resource} in ${org}`;
  if (resource ?? login) return `${resource ?? login} in ${org}`;
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
    case "insufficient_privileges":
    case "dependency_violation":
    case "already_exists":
    case "validation_error":
    case "unknown":
      return `GitHub refused the connector's request for ${org}${
        error.status === undefined ? "" : ` (${error.status})`
      }: ${error.githubMessages.join("; ")}`;
    default:
      throw throwAssertNever(type);
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
  const { org, repo, team } = target;
  if (error instanceof ConnectorError) return error;

  if (error instanceof RepositoryNotVisibleError) {
    return repositoryNotVisible(target, error.repo);
  }

  if (error instanceof TeamNotFoundError) {
    return teamNotFound(target, error.teamId);
  }

  if (error instanceof TeamChangeRefusedError) {
    return teamChangeRefused(target, error.githubMessages);
  }

  if (error instanceof BranchNotProtectedError) {
    return branchNotProtected(org, error.target);
  }

  if (error instanceof ReviewsNotRequiredError) {
    return reviewsNotRequired(org, error.target);
  }

  if (error instanceof WildcardRuleError) {
    return wildcardRule(org, error.target);
  }

  if (error instanceof BypassChangeRefusedError) {
    return bypassChangeRefused(target, error.target, error.githubMessages);
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
    if (isIpNotAllowed(error)) return ipNotAllowed(org);
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
        ...(team ? { team } : {}),
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
