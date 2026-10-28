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

import type { BypassAllowances } from "../../github/api.ts";
import {
  type ConnectGitHub,
  type GitHubClient,
  connectGitHub,
} from "../../github/client.ts";
import {
  BranchNotProtectedError,
  type GitHubTarget,
  ReviewsNotRequiredError,
  WildcardRuleError,
  callGitHub,
} from "../../github/errors.ts";
import {
  listUsers,
  newUserPrimitives,
  onlyPolicy,
  refuseNonMember,
} from "../common/handler.ts";
import { branch as branchName, spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

type Target = { org: string; repo: string; branch: string; login: string };

/**
 * How many times a change to the bypass list is made before giving up. Each
 * one is read back, and made again when someone else's change to the list
 * landed between the read and the write and dropped it.
 */
const MAX_CHANGES = 3;

const notOrgMember = ({ org, repo, branch, login }: Target) =>
  new ConnectorError({
    type: "validation_error",
    message: `${login} isn't a member of ${org}, so P0 can't let them bypass reviews on ${repo}'s ${branch} branch. Add them to the org first.`,
    payload: { reason: "not_org_member", org, repo, branch, login },
  });

const changeNotKept = (
  { org, repo, branch, login }: Target,
  allowed: boolean
) =>
  new ConnectorError({
    type: "validation_error",
    message: `GitHub didn't keep P0's change to who can bypass reviews on ${repo}'s ${branch} branch, so ${login} ${
      allowed ? "may not be able to" : "may still be able to"
    } force-merge there. Something else may be changing the branch's protection rule at the same time. Retry, or check the rule's bypass list in ${repo}'s branch settings.`,
    payload: { reason: "change_not_kept", org, repo, branch, login },
  });

const ruleOutlivedBranch = ({ org, repo, branch, login }: Target) =>
  new ConnectorError({
    type: "validation_error",
    message: `${repo} has no ${branch} branch any more, but its protection rule for ${branch} is still there, so P0 couldn't take ${login} off the rule's bypass list. Remove them from the rule in ${repo}'s branch settings.`,
    payload: { reason: "rule_outlived_branch", org, repo, branch, login },
  });

const hasAllowance = ({ users }: BypassAllowances, login: string) =>
  users.some((user) => user.toLowerCase() === login.toLowerCase());

/**
 * Whether a revoke that found no bypass list to read has nothing left to
 * remove: the grant only ever adds to the list of a rule named exactly for
 * the branch.
 *
 * Without such a rule, or without required reviews, that list is gone. A
 * branch that isn't there any more can still have its rule, though, and the
 * rule its list, which REST can't change without the branch.
 */
const verifyNothingToRemove = async (
  github: GitHubClient,
  { repo, branch }: Target,
  error: unknown
): Promise<boolean> => {
  if (error instanceof WildcardRuleError) return true;
  if (error instanceof ReviewsNotRequiredError) return true;
  if (!(error instanceof BranchNotProtectedError)) return false;
  return !(await github.listProtectionPatterns({ repo })).includes(branch);
};

/**
 * The branch's bypass list, or `undefined` for a revoke when the branch has no
 * list P0 could have added to, so there's nothing to remove.
 */
const fetchListToChange = async (
  github: GitHubClient,
  log: Logger,
  target: Target,
  allowed: boolean
): Promise<BypassAllowances | undefined> => {
  const { repo, branch } = target;
  try {
    return await github.fetchBypassAllowances({ repo, branch });
  } catch (error) {
    if (!allowed && (await verifyNothingToRemove(github, target, error))) {
      log.info(
        "the branch has no bypass list P0 could have added to, so there's nothing to remove"
      );
      return undefined;
    }
    if (error instanceof BranchNotProtectedError && !allowed) {
      throw ruleOutlivedBranch(target);
    }
    throw error;
  }
};

/**
 * Leaves `login` on the branch's bypass list, or off it.
 *
 * GitHub replaces the whole list on every change, so the list is read, the
 * login added or removed, and all of it written back with everyone else's
 * entries. A change made by someone else in between can drop P0's, so the
 * list is read again after each write, until it says what P0 wants or
 * {@link MAX_CHANGES} writes have been made.
 */
const setAllowance = async (
  github: GitHubClient,
  log: Logger,
  target: Target,
  allowed: boolean
) => {
  const { repo, branch, login } = target;

  for (let changes = 0; ; changes++) {
    const allowances = await fetchListToChange(github, log, target, allowed);
    if (allowances === undefined) return;
    if (hasAllowance(allowances, login) === allowed) {
      log.info(
        allowed
          ? "the user can bypass the branch's reviews"
          : "the user can't bypass the branch's reviews"
      );
      return;
    }
    if (changes === MAX_CHANGES) {
      log.warn({ changes }, "GitHub didn't keep the bypass list change");
      throw changeNotKept(target, allowed);
    }
    await github.setBypassAllowances({
      repo,
      branch,
      allowances: {
        ...allowances,
        users: allowed
          ? [...allowances.users, login]
          : allowances.users.filter(
              (user) => user.toLowerCase() !== login.toLowerCase()
            ),
      },
    });
  }
};

/**
 * The GitHub `force-merge` access: a place on one branch's list of who can
 * merge without its required pull request reviews, granted just in time and
 * restored at expiry.
 *
 * Like the `role` and `team` accesses, the "user" is an org member's login,
 * only `setPoliciesForUser` changes anything in GitHub, and every call acts as
 * the customer's own GitHub App.
 *
 * Exported separately from {@link router} so the primitives can be driven
 * against a {@link GitHubClient} double.
 */
export const newForceMergePrimitives = (
  logger: Logger,
  connect: ConnectGitHub
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  ...newUserPrimitives<ResourceSchema>(logger, connect, {
    grants: "force-merge access",
  }),

  /**
   * Leaves `login` on the policy's branch's bypass list when `allowed`, and
   * off it otherwise.
   *
   * A grant sends `true`, and a revoke whether the user was on the list
   * before the grant. The connector doesn't tell them apart. A place on the
   * list goes to an active org member only, on a branch whose protection rule
   * names it exactly and requires reviews. A removal works for anyone, and
   * succeeds when there's no such rule any more: the list went with it.
   */
  setPoliciesForUser: async (context, login, _user, policies) => {
    const { requestId, org } = context;
    const { repo, branch, allowed } = onlyPolicy(policies, {
      requestId,
      access: "GitHub force-merge access",
    });
    const log = logger.child({ requestId, org, repo, branch, login, allowed });
    const target: Target = { org, repo, branch, login };
    const githubTarget: GitHubTarget = {
      org,
      repo,
      login,
      changingAccess: true,
    };
    const github = await connect(context);
    if (allowed) {
      await callGitHub(
        () =>
          refuseNonMember(github, log, {
            login,
            grants: "force-merge access",
            notOrgMember: () => notOrgMember(target),
          }),
        githubTarget
      );
    }
    await callGitHub(
      () => setAllowance(github, log, target, allowed),
      githubTarget
    );
  },

  list: async (query) => {
    const { org } = query.context;
    const github = await connect(query.context);
    switch (query.type) {
      case "bypass-allowance": {
        const { repo, branch, login } = query;
        const allowances = await callGitHub(
          () => github.fetchBypassAllowances({ repo, branch }),
          { org, repo, login }
        );
        return hasAllowance(allowances, login)
          ? [{ key: login, value: login }]
          : [];
      }
      case "protected-branch": {
        const { repo } = query;
        const patterns = await callGitHub(
          () => github.listProtectionPatterns({ repo }),
          { org, repo }
        );
        // A pattern that's a branch name names that branch exactly. Anything
        // else is a wildcard rule, which a grant refuses.
        return patterns
          .filter((pattern) => branchName.safeParse(pattern).success)
          .map((pattern) => ({ key: pattern, value: pattern }));
      }
      case "member":
      case "account":
        return listUsers(github, query);
      default:
        throw throwAssertNever(query);
    }
  },
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newForceMergePrimitives(ctx.logger, connectGitHub)
  );
