import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector-core";

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
import {
  listUsers,
  newUserPrimitives,
  onlyPolicy,
  refuseNonMember,
} from "../common/handler.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

type Target = { org: string; repo: string; login: string };

const notOrgMember = ({ org, repo, login }: Target) =>
  new ConnectorError({
    type: "validation_error",
    message: `${login} isn't a member of ${org}, so P0 can't give them a role on ${repo}. Add them to the org first.`,
    payload: { reason: "not_org_member", org, repo, login },
  });

// A `validation_error`, because that is the type whose message P0 shows. P0
// never cancels the invitation, so the message asks the admin to.
const invitationPending = (
  { org, repo, login }: Target,
  invitationId: number | undefined
) =>
  new ConnectorError({
    type: "validation_error",
    message: `${login} isn't a member of ${org}, so P0 can't give them a role on ${repo}. GitHub sent ${login} an invitation to ${repo}. Cancel it in the repo's collaborator settings, then add ${login} to ${org} and request again.`,
    payload: {
      reason: "invitation_pending",
      org,
      repo,
      login,
      ...(invitationId !== undefined ? { invitationId } : {}),
    },
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
const isBelowBasePermission = (error: unknown): error is GitHubError =>
  error instanceof GitHubError &&
  (error.status === 422 || error.status === 403) &&
  error.githubMessages.some((message) => message.startsWith("Cannot assign"));

/** The org's base permission, or `undefined`: GitHub only shows it to some tokens. */
const fetchVisibleBasePermission = (github: GitHubClient, log: Logger) =>
  github.fetchBasePermission().catch((error: unknown) => {
    log.debug({ error }, "couldn't read the org's base permission");
    return undefined;
  });

/**
 * PUTs `login`'s direct role on the repo, and refuses to do anything else.
 *
 * GitHub answers a PUT for someone who isn't a collaborator yet and isn't an
 * org member by inviting them (201). {@link setRole} checks membership first,
 * so this only happens when the user leaves the org between that check and
 * the PUT. P0 makes no invitation call, so the call fails and the invitation
 * is left for the admin to cancel.
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
  throw invitationPending(target, invitationId);
};

/**
 * Takes back a role that went through for someone who left the org during
 * the call, then refuses it.
 *
 * The direct role is removed, whatever it was before: P0 gives non-members no
 * role.
 */
const takeBackRole = async (
  github: GitHubClient,
  log: Logger,
  target: Target,
  role: string
): Promise<never> => {
  log.warn(
    { role },
    "the user left the org while P0 set their role, so P0 removes the direct role"
  );
  await github.removeCollaborator(target.repo, target.login);
  log.info({ role }, "removed the direct role P0 set");
  throw notOrgMember(target);
};

/**
 * Sets `login`'s direct role to `role`, for an active org member only.
 *
 * GitHub would take the PUT for a non-member too: it invites someone outside
 * the org, and sets the role outright for an existing outside collaborator. P0
 * gives roles to org members only and never invites anyone, so membership is
 * checked before anything changes, and again after the `PUT`: someone who left
 * the org in between gets an invitation, which `putRole` refuses, or, as an
 * existing outside collaborator, the role, which {@link takeBackRole} takes
 * back.
 */
const setRole = async (
  github: GitHubClient,
  log: Logger,
  target: Target,
  role: string
) => {
  await refuseNonMember(github, log, {
    login: target.login,
    grants: "a role",
    notOrgMember: () => notOrgMember(target),
  });
  try {
    await putRole(github, log, target, role);
  } catch (error) {
    if (!isBelowBasePermission(error)) throw error;
    throw belowBasePermission(
      target,
      role,
      await fetchVisibleBasePermission(github, log)
    );
  }
  if (!(await github.verifyOrgMembership(target.login))) {
    await takeBackRole(github, log, target, role);
  }
  log.info({ role }, "set the repository role");
};

/**
 * Removes `login`'s direct role on the repo, member or not. GitHub answers the
 * `DELETE` the same whether or not they had one, so running it again changes
 * nothing.
 */
const removeRole = async (
  github: GitHubClient,
  log: Logger,
  target: Target
) => {
  await github.removeCollaborator(target.repo, target.login);
  log.info("removed the direct role");
};

/**
 * The GitHub `role` access: a direct collaborator role on one
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
  ...newUserPrimitives<ResourceSchema>(logger, connect, { grants: "a role" }),

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
    const { repo, role } = onlyPolicy(policies, {
      requestId,
      access: "a GitHub repository role",
    });
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
          "the repository isn't in the app's repository selection, so the role needs manual intervention"
        );
      }
      throw toConnectorError(error, { ...target, changingAccess: true });
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
        // Custom repository roles only exist on Enterprise Cloud. Anywhere
        // else the call fails, and the built-in roles are the whole list.
        const customRoles = await github
          .listCustomRoles()
          .catch((error: unknown) => {
            logger.info(
              { org, error },
              "couldn't list custom repository roles, so P0 lists the built-in roles only"
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
          () => github.fetchDirectRole(repo, login),
          { org, repo, login }
        );
        return role === null ? [] : [{ key: role, value: role }];
      }
      case "member":
      case "account":
        return listUsers(github, query);
      case "repository-id": {
        const { repo } = query;
        const repository = await callGitHub(
          () => github.fetchRepository(repo),
          { org, repo }
        );
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
