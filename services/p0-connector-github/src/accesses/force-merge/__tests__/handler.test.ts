import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  CONTEXT,
  CREDENTIALS,
  LOGIN,
  connectorError,
  newGitHub,
  newRecordingLogger,
} from "../../../github/__tests__/doubles.ts";
import type { BypassAllowances } from "../../../github/api.ts";
import type { ConnectGitHub } from "../../../github/client.ts";
import {
  BranchNotProtectedError,
  BypassChangeRefusedError,
  MissingPermissionsError,
  ReviewsNotRequiredError,
  WildcardRuleError,
} from "../../../github/errors.ts";
import { newForceMergePrimitives } from "../handler.ts";

const BRANCH = { repo: "api", branch: "main" };

/** A bypass list with someone else's entries on it. */
const OTHERS: BypassAllowances = {
  users: ["hubot"],
  teams: ["release-managers"],
  apps: ["deploy-bot"],
};

let github: ReturnType<typeof newGitHub>;
let connect: ReturnType<typeof vi.fn<ConnectGitHub>>;
let logs: ReturnType<typeof newRecordingLogger>;
let perimeter: ReturnType<typeof newForceMergePrimitives>;

const set = (allowed: boolean) =>
  perimeter.setPoliciesForUser(CONTEXT, LOGIN, LOGIN, [{ ...BRANCH, allowed }]);

/** The bypass list `read` returns, one per read, the last one from then on. */
const readsInTurn = (...reads: BypassAllowances[]) => {
  for (const read of reads) {
    github.fetchBypassAllowances.mockResolvedValueOnce(read);
  }
  github.fetchBypassAllowances.mockResolvedValue(reads[reads.length - 1]);
};

const withLogin = (list: BypassAllowances, login = LOGIN) => ({
  ...list,
  users: [...list.users, login],
});

beforeEach(() => {
  github = newGitHub();
  connect = vi.fn<ConnectGitHub>(async () => github);
  logs = newRecordingLogger();
  perimeter = newForceMergePrimitives(logs.log, connect);
});

// The user primitives are shared with the `role` access, whose tests cover
// them. Only what the access passes them is checked here.
it("createUser refuses the grant, naming what it would have given", async () => {
  const data = await connectorError(() => perimeter.createUser(CONTEXT, LOGIN));

  expect(data.payload.reason).toBe("user_not_found");
  expect(data.message).toBe(
    "GitHub user octocat doesn't exist any more, so P0 can't give them force-merge access in acme. Request access again with their current GitHub account."
  );
});

describe("setPoliciesForUser: a grant", () => {
  it("adds the login to an empty list", async () => {
    readsInTurn(
      { users: [], teams: [], apps: [] },
      withLogin({ users: [], teams: [], apps: [] })
    );

    await set(true);

    expect(github.fetchBypassAllowances).toHaveBeenCalledWith(BRANCH);
    expect(github.setBypassAllowances).toHaveBeenCalledTimes(1);
    expect(github.setBypassAllowances).toHaveBeenCalledWith({
      ...BRANCH,
      allowances: { users: [LOGIN], teams: [], apps: [] },
    });
  });

  it("keeps everyone else's entries, users, teams and apps", async () => {
    readsInTurn(OTHERS, withLogin(OTHERS));

    await set(true);

    expect(github.setBypassAllowances).toHaveBeenCalledWith({
      ...BRANCH,
      allowances: withLogin(OTHERS),
    });
  });

  it("changes nothing when the login is already listed, in any case", async () => {
    readsInTurn(withLogin(OTHERS, "OctoCat"));

    await set(true);

    expect(github.setBypassAllowances).not.toHaveBeenCalled();
  });

  // Someone else's write between the read and P0's can drop P0's entry.
  it("writes again when the list read back doesn't have the login", async () => {
    readsInTurn(OTHERS, OTHERS, withLogin(OTHERS));

    await set(true);

    expect(github.setBypassAllowances).toHaveBeenCalledTimes(2);
  });

  it("gives up after three writes GitHub didn't keep", async () => {
    readsInTurn(OTHERS);

    const data = await connectorError(() => set(true));

    expect(github.setBypassAllowances).toHaveBeenCalledTimes(3);
    expect(github.fetchBypassAllowances).toHaveBeenCalledTimes(4);
    expect(data.type).toBe("validation_error");
    expect(data.payload.reason).toBe("change_not_kept");
    expect(data.message).toBe(
      "GitHub didn't keep P0's change to who can bypass reviews on api's main branch, so octocat may not be able to force-merge there. Something else may be changing the branch's protection rule at the same time. Retry, or check the rule's bypass list in api's branch settings."
    );
  });

  it("refuses a non-member, changing nothing", async () => {
    github.verifyOrgMembership.mockResolvedValue(false);

    const data = await connectorError(() => set(true));

    expect(github.verifyOrgMembership).toHaveBeenCalledWith(LOGIN);
    expect(data.type).toBe("validation_error");
    expect(data.payload).toEqual({
      reason: "not_org_member",
      org: "acme",
      repo: "api",
      branch: "main",
      login: LOGIN,
    });
    expect(data.message).toBe(
      "octocat isn't a member of acme, so P0 can't let them bypass reviews on api's main branch. Add them to the org first."
    );
    expect(github.fetchBypassAllowances).not.toHaveBeenCalled();
    expect(github.setBypassAllowances).not.toHaveBeenCalled();
  });

  it.each([
    [
      "isn't protected",
      new BranchNotProtectedError(BRANCH),
      "branch_not_protected",
      "api's main branch isn't protected, or doesn't exist. Force-merge access needs a branch protection rule for exactly main that requires pull request reviews.",
    ],
    [
      "doesn't require reviews",
      new ReviewsNotRequiredError(BRANCH),
      "reviews_not_required",
      `api's main branch doesn't require pull request reviews, so there are none to bypass. Turn on "Require a pull request before merging" in the branch's protection rule.`,
    ],
    [
      "is protected by a wildcard rule only",
      new WildcardRuleError(BRANCH),
      "wildcard_rule",
      "api's main branch is protected by a wildcard rule, which other branches can share, so P0 won't change who can bypass it. Ask a repo admin to add a branch protection rule for exactly main.",
    ],
  ])(
    "refuses a branch that %s, changing nothing",
    async (_case, error, reason, message) => {
      github.fetchBypassAllowances.mockRejectedValue(error);

      const data = await connectorError(() => set(true));

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({
        reason,
        org: "acme",
        repo: "api",
        branch: "main",
      });
      expect(data.message).toBe(message);
      expect(github.setBypassAllowances).not.toHaveBeenCalled();
    }
  );

  // No write access to the repo, or a full list.
  it("reports GitHub refusing the change, keeping GitHub's words", async () => {
    github.setBypassAllowances.mockRejectedValue(
      new BypassChangeRefusedError(BRANCH, ["Validation Failed"])
    );

    const data = await connectorError(() => set(true));

    expect(data.type).toBe("validation_error");
    expect(data.payload).toEqual({
      reason: "bypass_change_refused",
      org: "acme",
      repo: "api",
      branch: "main",
      login: LOGIN,
    });
    expect(data.message).toBe(
      "GitHub refused to change who can bypass reviews on api's main branch (Validation Failed). Check that octocat has write access to api, and that the bypass list has room: GitHub allows 100 users, teams and apps in all."
    );
  });

  it("reports a missing permission as GitHub's", async () => {
    github.fetchBypassAllowances.mockRejectedValue(
      new MissingPermissionsError(["administration=read"])
    );

    const data = await connectorError(() => set(true));

    expect(data.type).toBe("insufficient_privileges");
  });
});

describe("setPoliciesForUser: a revoke", () => {
  it("removes the login and keeps everyone else's entries", async () => {
    readsInTurn(withLogin(OTHERS, "OctoCat"), OTHERS);

    await set(false);

    expect(github.setBypassAllowances).toHaveBeenCalledWith({
      ...BRANCH,
      allowances: OTHERS,
    });
  });

  it("changes nothing when the login isn't listed", async () => {
    readsInTurn(OTHERS);

    await set(false);

    expect(github.setBypassAllowances).not.toHaveBeenCalled();
  });

  it("works for someone who has left the org", async () => {
    github.verifyOrgMembership.mockResolvedValue(false);
    readsInTurn(withLogin(OTHERS), OTHERS);

    await set(false);

    expect(github.setBypassAllowances).toHaveBeenCalledTimes(1);
  });

  it("gives up after three writes GitHub didn't keep", async () => {
    readsInTurn(withLogin(OTHERS));

    const data = await connectorError(() => set(false));

    expect(github.setBypassAllowances).toHaveBeenCalledTimes(3);
    expect(data.message).toBe(
      "GitHub didn't keep P0's change to who can bypass reviews on api's main branch, so octocat may still be able to force-merge there. Something else may be changing the branch's protection rule at the same time. Retry, or check the rule's bypass list in api's branch settings."
    );
  });

  // The list P0 added to went with the rule, or with the required reviews.
  it.each([
    ["a wildcard rule only", new WildcardRuleError(BRANCH)],
    ["no required reviews", new ReviewsNotRequiredError(BRANCH)],
  ])("succeeds on a branch with %s", async (_case, error) => {
    github.fetchBypassAllowances.mockRejectedValue(error);

    await expect(set(false)).resolves.toBeUndefined();

    expect(github.setBypassAllowances).not.toHaveBeenCalled();
  });

  it("succeeds on a branch with no protection rule for it", async () => {
    github.fetchBypassAllowances.mockRejectedValue(
      new BranchNotProtectedError(BRANCH)
    );
    github.listProtectionPatterns.mockResolvedValue(["release/*"]);

    await expect(set(false)).resolves.toBeUndefined();

    expect(github.listProtectionPatterns).toHaveBeenCalledWith({ repo: "api" });
  });

  // GitHub can't show a branch that's gone, but its rule can still name the
  // user.
  it("fails when the branch is gone but its rule is still there", async () => {
    github.fetchBypassAllowances.mockRejectedValue(
      new BranchNotProtectedError(BRANCH)
    );
    github.listProtectionPatterns.mockResolvedValue(["main"]);

    const data = await connectorError(() => set(false));

    expect(data.type).toBe("validation_error");
    expect(data.payload.reason).toBe("rule_outlived_branch");
    expect(data.message).toBe(
      "api has no main branch any more, but its protection rule for main is still there, so P0 couldn't take octocat off the rule's bypass list. Remove them from the rule in api's branch settings."
    );
  });
});

describe("list", () => {
  const bypassAllowance = {
    type: "bypass-allowance" as const,
    context: CREDENTIALS,
    ...BRANCH,
    login: LOGIN,
  };

  it("reads a listed user as one item", async () => {
    readsInTurn(withLogin(OTHERS, "OctoCat"));

    await expect(perimeter.list(bypassAllowance)).resolves.toEqual([
      { key: LOGIN, value: LOGIN },
    ]);
    expect(github.fetchBypassAllowances).toHaveBeenCalledWith(BRANCH);
  });

  it("reads a user who isn't listed as none", async () => {
    readsInTurn(OTHERS);

    await expect(perimeter.list(bypassAllowance)).resolves.toEqual([]);
  });

  it("refuses to read a branch it couldn't grant on", async () => {
    github.fetchBypassAllowances.mockRejectedValue(
      new WildcardRuleError(BRANCH)
    );

    const data = await connectorError(() => perimeter.list(bypassAllowance));

    expect(data.payload.reason).toBe("wildcard_rule");
  });

  it("lists the branches with a rule of their own, leaving out wildcard rules", async () => {
    github.listProtectionPatterns.mockResolvedValue([
      "main",
      "release/*",
      "release/2026.10",
      "[ab]*",
    ]);

    await expect(
      perimeter.list({
        type: "protected-branch",
        context: CREDENTIALS,
        repo: "api",
      })
    ).resolves.toEqual([
      { key: "main", value: "main" },
      { key: "release/2026.10", value: "release/2026.10" },
    ]);
    expect(github.listProtectionPatterns).toHaveBeenCalledWith({ repo: "api" });
  });
});
