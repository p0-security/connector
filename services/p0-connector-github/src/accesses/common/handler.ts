import {
  ConnectorError,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchema,
  throwAssertNever,
} from "@p0security/connector-core";

import type { ConnectGitHub, GitHubClient } from "../../github/client.ts";
import { callGitHub } from "../../github/errors.ts";
import type { RequestContext, UserQuery } from "./definition.ts";

/** A schema whose users are the ones every access shares: an org member's
 * login, found through the request context's GitHub user id. */
type UserSchema = ResourceRootSchema & {
  UserBody: string;
  RequestContext: RequestContext;
};

// A `validation_error`, so P0 shows the message. GitHub answers 404 for a
// deleted account, and also for some that still exist, such as a spam-flagged
// one.
const userNotFound = (
  org: string,
  login: string,
  githubUserId: string,
  grants: string
) =>
  new ConnectorError({
    type: "validation_error",
    message: `GitHub user ${login} doesn't exist any more, so P0 can't give them ${grants} in ${org}. Request access again with their current GitHub account.`,
    payload: { reason: "user_not_found", org, login, githubUserId },
  });

/**
 * The user primitives every access shares. The "user" is an org member's
 * login, and none of these changes anything in GitHub.
 *
 * `grants` names what the access gives a user, such as "a role", for the
 * message that refuses a grant.
 */
export const newUserPrimitives = <Schema extends UserSchema>(
  logger: Logger,
  connect: ConnectGitHub,
  { grants }: { grants: string }
): Pick<
  ResourceRootConnectorPrimitives<Schema>,
  "createUser" | "deleteUser" | "getUser" | "validation"
> => ({
  // A GitHub login can't carry a P0 marker, so there's nothing to validate a
  // user's namespace against.
  validation: () => ({ user: null }),

  /**
   * The login the account with the context's GitHub user id has now, or
   * `null` when GitHub has no account with that id.
   *
   * A login can be renamed, and access moves with the account, so the old
   * login can end up naming someone else. The user id this returns is the
   * current login, and that's the login `setPoliciesForUser` acts on.
   *
   * `null` is how P0 learns there's no user. A grant then calls `createUser`,
   * which refuses it. A revoke stops before it changes anything: an account
   * that doesn't exist holds no access, so it's already revoked.
   *
   * Membership isn't checked here: a member converted to an outside
   * collaborator keeps their direct role, and must still be revoked.
   */
  getUser: async (context, login) => {
    const { requestId, org, githubUserId } = context;
    const log = logger.child({ requestId, org, login, githubUserId });
    const github = await connect(context);
    const currentLogin = await callGitHub(
      () => github.fetchCurrentLogin(githubUserId),
      { org, login }
    );
    if (currentLogin === null) {
      log.warn("GitHub shows no account with this id");
      return null;
    }
    if (currentLogin.toLowerCase() !== login.toLowerCase()) {
      log.info(
        { currentLogin },
        "the account's login changed since the request, so P0 acts on its current login"
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
    throw userNotFound(org, login, githubUserId, grants);
  },

  /**
   * A no-op, and this is load-bearing.
   *
   * The revoke already happened in `setPoliciesForUser`, which put the user's
   * prior access back. Removing anything here would wipe it out.
   */
  deleteUser: async (context, login) => {
    logger.debug(
      { requestId: context.requestId, login },
      "deleteUser is a no-op, since the revoke puts the prior access back"
    );
  },
});

/** Answers the lookups every access's lister shares. */
export const listUsers = async (
  github: Pick<GitHubClient, "fetchAccount" | "findMemberLogin">,
  query: UserQuery
): Promise<{ key: string; value: string }[]> => {
  const { org } = query.context;
  switch (query.type) {
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
      const account = await callGitHub(() => github.fetchAccount(login), {
        org,
        login,
      });
      // `[]` when GitHub has no account with that login.
      return account === null
        ? []
        : [{ key: account.githubUserId, value: account.login }];
    }
    default:
      throw throwAssertNever(query);
  }
};

/**
 * The one policy P0 sends `setPoliciesForUser`: the access to leave the user
 * with. `access` names it for the error, such as "a GitHub repository role".
 */
export const onlyPolicy = <Policy>(
  policies: Policy[],
  { requestId, access }: { requestId: string; access: string }
): Policy => {
  const [policy, ...others] = policies;
  if (policy === undefined || others.length > 0) {
    // `unknown`, not `validation_error`: P0 sends exactly one policy, so
    // anything else is a P0 bug the requestor can't correct.
    throw new ConnectorError({
      type: "unknown",
      message: `Expected exactly 1 policy for ${access}, got ${policies.length}`,
      payload: { requestId, nPolicies: policies.length },
    });
  }
  return policy;
};

/**
 * Refuses a grant to someone who isn't an active org member, and returns for
 * one who is.
 */
export const refuseNonMember = async (
  github: Pick<GitHubClient, "verifyOrgMembership">,
  log: Logger,
  params: {
    login: string;
    /** What the access gives a user, such as "a role", for the log. */
    grants: string;
    notOrgMember: () => Error;
  }
): Promise<void> => {
  const { login, grants, notOrgMember } = params;
  if (await github.verifyOrgMembership(login)) return;
  log.info(`refused ${grants} to someone who isn't an org member`);
  throw notOrgMember();
};
