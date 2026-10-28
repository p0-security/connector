import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector";

import { GitHubError } from "../../github/api.ts";
import {
  type ConnectGitHub,
  type GitHubClient,
  connectGitHub,
} from "../../github/client.ts";
import {
  RepositoryNotVisibleError,
  callGitHub,
  toConnectorError,
} from "../../github/errors.ts";
import { BUILT_IN_ROLES, displayRole } from "../../github/roles.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

type Target = { org: string; repo: string; login: string };

const notOrgMember = ({ org, repo, login }: Target) =>
  new ConnectorError({
    type: "validation_error",
    message: `${login} isn't a member of ${org}, so P0 can't give them a role on ${repo}. Add them to the org first.`,
    payload: { reason: "not_org_member", org, repo, login },
  });

// A `validation_error`, so P0 shows the message. GitHub answers 404 for a
// deleted account, and also for some that still exist, such as a spam-flagged
// one.
const userNotFound = (org: string, login: string, githubUserId: string) =>
  new ConnectorError({
    type: "validation_error",
    message: `GitHub user ${login} doesn't exist any more, so P0 can't give them a role in ${org}. Request access again with their current GitHub account.`,
    payload: { reason: "user_not_found", org, login, githubUserId },
  });

// A `validation_error`, because that is the type whose message P0 shows. P0
// still retries the step, and the retried grant finds the user isn't a member
// and tries the cancel again, so this is the outcome only when every attempt
// fails to cancel.
const invitationPending = (
  { org, repo, login }: Target,
  invitationId: number | undefined
) =>
  new ConnectorError({
    type: "validation_error",
    message: `${login} isn't a member of ${org}, so P0 can't give them a role on ${repo}. GitHub may have sent them an invitation to ${repo} instead, and P0 couldn't make sure it was cancelled. Check the repo's collaborator settings, and cancel any pending invitation from the GitHub App.`,
    payload: {
      reason: "invitation_pending",
      org,
      repo,
      login,
      ...(invitationId !== undefined ? { invitationId } : {}),
    },
  });

// The same reason as a grant's, for a removal that left a non-member with no
// direct role but couldn't make sure the app's invitations to them are gone. A
// retry tries the cancel again.
const invitationPendingAfterRevoke = ({ org, repo, login }: Target) =>
  new ConnectorError({
    type: "validation_error",
    message: `${login} isn't a member of ${org} and has no direct role on ${repo}, but P0 couldn't make sure an invitation it sent to ${login} for ${repo} was cancelled. Check the repo's collaborator settings, and cancel any pending invitation from the GitHub App.`,
    payload: { reason: "invitation_pending", org, repo, login },
  });

const belowBasePermission = (
  { org, repo, login }: Target,
  role: string,
  base: string | undefined
) =>
  new ConnectorError({
    type: "validation_error",
    message: base
      ? `${org}'s base permission is ${displayRole(base)}, which is higher than ${displayRole(role)}. Request ${displayRole(base)} or higher.`
      : `${org}'s base permission is higher than ${displayRole(role)}. Request a role at or above the org's base permission.`,
    payload: {
      reason: "below_base_permission",
      org,
      repo,
      login,
      role,
      ...(base ? { basePermission: base } : {}),
    },
  });

/**
 * GitHub refuses a role below the org's base permission with a message that
 * starts "Cannot assign". The docs don't say whether that comes as a 422 or a
 * 403, so either counts.
 */
const isBelowBasePermission = (error: unknown) =>
  error instanceof GitHubError &&
  (error.status === 422 || error.status === 403) &&
  error.githubMessages.some((message) => message.startsWith("Cannot assign"));

/** The org's base permission, or `undefined`: GitHub only shows it to some tokens. */
const readBasePermission = (github: GitHubClient, log: Logger) =>
  github.basePermission().catch((error: unknown) => {
    log.debug({ error }, "couldn't read the org's base permission");
    return undefined;
  });

/**
 * How cancelling the app's invitations went: `cancelled` at least one,
 * `failed` somewhere along the way, so one may still be live, or `none_found`
 * to cancel.
 */
type CancelOutcome = "cancelled" | "failed" | "none_found";

/**
 * Cancels the pending invitations to the repo that this app sent `login`.
 *
 * With an `invitationId` (from a 201), that one goes first. Otherwise, or if
 * that fails, the repo's invitations are searched for the ones the app's
 * `<slug>[bot]` user sent `login`, and each is cancelled. An invitation an
 * admin sent is never touched. The whole sequence shares one token.
 *
 * After a 201, GitHub said it sent one, so any failure is `failed`. Without
 * one, nothing suggests an invitation exists until the search has started, so
 * a failure getting there (minting the write token, reading the app's slug) is
 * thrown. It then reaches P0 with its own reason, such as a missing
 * `administration: write`, a suspended installation or rejected credentials,
 * rather than as a possible invitation that no retry would clear.
 */
const cancelAppInvitations = async (
  github: GitHubClient,
  log: Logger,
  { repo, login }: Target,
  invitationId: number | undefined
): Promise<CancelOutcome> => {
  let searching = false;
  try {
    const invitations = await github.repositoryInvitations(repo);
    if (invitationId !== undefined) {
      try {
        await invitations.cancel(invitationId);
        log.info({ invitationId }, "cancelled the repository invitation");
        return "cancelled";
      } catch (error) {
        log.warn(
          { error, invitationId },
          "couldn't cancel the repository invitation by its id; looking it up"
        );
      }
    }
    const inviter = await github.appBotLogin();
    searching = true;
    const ids = await invitations.findInvitationIds({
      invitee: login,
      inviter,
    });
    for (const id of ids) await invitations.cancel(id);
    if (ids.length === 0) return "none_found";
    log.info(
      { invitationIds: ids },
      "cancelled the app's pending repository invitations"
    );
    return "cancelled";
  } catch (error) {
    if (invitationId === undefined && !searching) throw error;
    log.error(
      { error, invitationId },
      "failed to cancel the app's repository invitation; one may still be live"
    );
    return "failed";
  }
};

/**
 * For a removal that leaves a non-member with no direct role: cancels any
 * invitation the app sent them, so a revoke never ends with one pending.
 *
 * A grant whose `PUT` became an invitation it couldn't cancel leaves one
 * behind, and P0's rollback of that grant can be a removal that ends here.
 */
const cancelInvitationsAfterRevoke = async (
  github: GitHubClient,
  log: Logger,
  target: Target
) => {
  if (
    (await cancelAppInvitations(github, log, target, undefined)) === "failed"
  ) {
    throw invitationPendingAfterRevoke(target);
  }
};

/**
 * PUTs `login`'s direct role on the repo, and refuses to do anything else.
 *
 * GitHub answers a PUT for someone who isn't a collaborator yet and isn't an
 * org member by inviting them (201). {@link setRole} checks membership first,
 * so this only happens when the user leaves the org between that check and
 * the PUT. P0 never invites anyone, so the invitation is cancelled and the
 * call fails.
 */
const putRole = async (
  github: GitHubClient,
  log: Logger,
  target: Target,
  role: string
) => {
  const { invited, invitationId } = await github.putRole(
    target.repo,
    target.login,
    role
  );
  if (!invited) return;

  log.warn(
    { role, invitationId },
    "GitHub invited a non-member instead of setting a role"
  );
  // GitHub said it sent one, so finding none to cancel isn't proof it's gone.
  if (
    (await cancelAppInvitations(github, log, target, invitationId)) !==
    "cancelled"
  ) {
    throw invitationPending(target, invitationId);
  }
  throw notOrgMember(target);
};

/**
 * Takes back a role that went through for someone who left the org during
 * the call, then refuses it.
 *
 * The direct role is removed, whatever it was before: P0 gives non-members no
 * role. Then, as for any non-member, the app's invitations to them are
 * cancelled.
 */
const takeBackRole = async (
  github: GitHubClient,
  log: Logger,
  target: Target,
  role: string
): Promise<never> => {
  log.warn(
    { role },
    "the user left the org while P0 set their role; removing the direct role"
  );
  await github.removeCollaborator(target.repo, target.login);
  log.info({ role }, "removed the direct role P0 set");
  if (
    (await cancelAppInvitations(github, log, target, undefined)) === "failed"
  ) {
    throw invitationPending(target, undefined);
  }
  throw notOrgMember(target);
};

/**
 * Sets `login`'s direct role to `role`, for an active org member only.
 *
 * GitHub would take the PUT for a non-member too: it invites someone outside
 * the org, and sets the role outright for an existing outside collaborator. P0
 * gives roles to org members only and never invites anyone, so membership is
 * checked before anything changes, and again after the `PUT`: someone who left
 * the org in between gets an invitation, which `putRole` cancels, or, as an
 * existing outside collaborator, the role, which {@link takeBackRole} takes
 * back.
 *
 * A non-member's refusal first cancels any invitation this app sent them. An
 * earlier attempt whose PUT became an invitation it couldn't cancel leaves one
 * behind, and P0 retries the call, so this is where the retry clears it.
 */
const setRole = async (
  github: GitHubClient,
  log: Logger,
  target: Target,
  role: string
) => {
  if (!(await github.isMember(target.login))) {
    if (
      (await cancelAppInvitations(github, log, target, undefined)) === "failed"
    ) {
      throw invitationPending(target, undefined);
    }
    log.info({ role }, "refused a role to someone who isn't an org member");
    throw notOrgMember(target);
  }
  try {
    await putRole(github, log, target, role);
  } catch (error) {
    if (!isBelowBasePermission(error)) throw error;
    throw belowBasePermission(
      target,
      role,
      await readBasePermission(github, log)
    );
  }
  if (!(await github.isMember(target.login))) {
    await takeBackRole(github, log, target, role);
  }
  log.info({ role }, "set the repository role");
};

/**
 * Removes `login`'s direct role on the repo, member or not. GitHub answers the
 * `DELETE` the same whether or not they had one, so running it again changes
 * nothing.
 *
 * A non-member also has the app's invitations to them cancelled: a grant
 * whose `PUT` became an invitation it couldn't cancel leaves one behind.
 */
const removeRole = async (
  github: GitHubClient,
  log: Logger,
  target: Target
) => {
  await github.removeCollaborator(target.repo, target.login);
  log.info("removed the direct role");
  if (!(await github.isMember(target.login))) {
    await cancelInvitationsAfterRevoke(github, log, target);
  }
};

/**
 * The GitHub Repositories `role` access: a direct collaborator role on one
 * repository, granted just in time and restored at expiry.
 *
 * The "user" is an org member's login, and only `setPoliciesForUser` changes
 * anything in GitHub. Every call acts as the customer's own GitHub App, whose
 * key the connector reads from the customer's vault, so P0 holds no GitHub
 * credential at all.
 *
 * Exported separately from {@link router} so the primitives can be driven
 * against a {@link GitHubClient} double.
 */
export const newRolePrimitives = (
  logger: Logger,
  connect: ConnectGitHub
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  // A GitHub login can't carry a P0 marker, so there's nothing to validate a
  // user's namespace against.
  validation: () => ({ user: null }),

  /**
   * The login the account with the context's GitHub user id has now, or
   * `null` when GitHub has no account with that id.
   *
   * A login can be renamed, and the role moves with the account, so the old
   * login can end up naming someone else. The user id this returns is the
   * current login, and that's the login `setPoliciesForUser` acts on.
   *
   * `null` is how P0 learns there's no user. A grant then calls `createUser`,
   * which refuses it. A revoke stops before it changes anything: an account
   * that doesn't exist holds no role, so it's already revoked.
   *
   * Membership isn't checked here: a member converted to an outside
   * collaborator keeps their direct role, and must still be revoked.
   */
  getUser: async (context, login) => {
    const { requestId, org, githubUserId } = context;
    const log = logger.child({ requestId, org, login, githubUserId });
    const github = await connect(context);
    const currentLogin = await callGitHub(
      () => github.currentLogin(githubUserId),
      { org, login }
    );
    if (currentLogin === null) {
      log.warn("GitHub shows no account with this id");
      return null;
    }
    if (currentLogin.toLowerCase() !== login.toLowerCase()) {
      log.info(
        { currentLogin },
        "the account's login changed since the request; acting on its current login"
      );
    }
    return currentLogin;
  },

  /**
   * Refuses the grant. P0 calls this only when `getUser` found no account
   * with the context's GitHub user id, and the connector can't create a
   * GitHub account.
   */
  createUser: async (context, login) => {
    const { requestId, org, githubUserId } = context;
    logger.info(
      { requestId, org, login, githubUserId },
      "refused a grant: GitHub shows no account with this id"
    );
    throw userNotFound(org, login, githubUserId);
  },

  /**
   * A no-op, and this is load-bearing.
   *
   * The revoke already happened in `setPoliciesForUser`, which put the prior
   * role back. Removing the collaborator here would wipe it out.
   */
  deleteUser: async (context, login) => {
    logger.debug(
      { requestId: context.requestId, login },
      "deleteUser is a no-op; the revoke puts the prior role back"
    );
  },

  /**
   * Leaves `login` with the policy's role on the policy's repo: `PUT`s a role,
   * or removes the direct role when it's `null`.
   *
   * A grant sends the requested role, and a revoke the role from before the
   * grant. The connector doesn't tell them apart, and doesn't compare the
   * role with the one there now: it sets it. A role goes to an active org
   * member only, and nobody is ever invited ({@link setRole}). A removal works
   * for anyone ({@link removeRole}).
   *
   * `login` is the user id `getUser` returned, so the login the account with
   * the context's GitHub user id has now.
   */
  setPoliciesForUser: async (context, login, _user, policies) => {
    const { requestId, org } = context;
    const [policy, ...others] = policies;
    if (policy === undefined || others.length > 0) {
      // `unknown`, not `validation_error`: P0 sends exactly one policy, the
      // role to leave the user with, so anything else is a P0 bug the
      // requestor can't correct.
      throw new ConnectorError({
        type: "unknown",
        message: `Expected exactly 1 policy for a GitHub repository role, got ${policies.length}`,
        payload: { requestId, nPolicies: policies.length },
      });
    }

    const { repo, role } = policy;
    const log = logger.child({ requestId, org, repo, login, role });
    const target: Target = { org, repo, login };
    const github = await connect(context);
    try {
      if (role === null) {
        await removeRole(github, log, target);
      } else {
        await setRole(github, log, target, role);
      }
    } catch (error) {
      if (error instanceof RepositoryNotVisibleError) {
        log.warn(
          "the repository isn't in the app's repository selection; the role needs manual intervention"
        );
      }
      throw toConnectorError(error, { ...target, changingRole: true });
    }
  },

  list: async (query) => {
    const { org } = query.context;
    const github = await connect(query.context);
    switch (query.type) {
      case "repository": {
        const repositories = await callGitHub(() => github.listRepositories(), {
          org,
        });
        // Keyed by the bare name, the form every other query and the request
        // context take a repo in.
        return repositories.map(({ name }) => ({ key: name, value: name }));
      }
      case "role": {
        // Custom repository roles only exist on Enterprise Cloud; anywhere
        // else the call fails and the built-in roles are the whole list.
        const customRoles = await github
          .listCustomRoles()
          .catch((error: unknown) => {
            logger.info(
              { org, error },
              "couldn't list custom repository roles; listing built-in roles only"
            );
            return [];
          });
        return [
          ...BUILT_IN_ROLES.map(({ key, value }) => ({ key, value })),
          ...customRoles.map((name) => ({ key: name, value: name })),
        ];
      }
      case "direct-role": {
        const { repo, login } = query;
        const role = await callGitHub(
          () => github.readDirectRole(repo, login),
          {
            org,
            repo,
            login,
          }
        );
        return role === null ? [] : [{ key: role, value: role }];
      }
      case "member": {
        const login = await callGitHub(
          () => github.findMemberLogin(query.email),
          { org }
        );
        // `[]` lets P0 tell the requestor to have their email domain verified.
        return login === null ? [] : [{ key: login, value: login }];
      }
      case "account": {
        const { login } = query;
        const account = await callGitHub(() => github.findAccount(login), {
          org,
          login,
        });
        // `[]` when GitHub has no account with that login.
        return account === null
          ? []
          : [{ key: account.githubUserId, value: account.login }];
      }
      case "repository-id": {
        const { repo } = query;
        const repository = await callGitHub(() => github.findRepository(repo), {
          org,
          repo,
        });
        // `[]` when the installation can't see a repository by that name.
        return repository === null
          ? []
          : [{ key: repository.repositoryId, value: repository.name }];
      }
      default:
        throw throwAssertNever(query);
    }
  },
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newRolePrimitives(ctx.logger, connectGitHub)
  );
