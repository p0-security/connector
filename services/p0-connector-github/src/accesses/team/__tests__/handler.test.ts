import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  CONTEXT,
  CREDENTIALS,
  LOGIN,
  connectorError,
  newGitHub,
  newRecordingLogger,
} from "../../../github/__tests__/doubles.ts";
import { GitHubError, type TeamRole } from "../../../github/api.ts";
import type { ConnectGitHub } from "../../../github/client.ts";
import {
  TeamChangeRefusedError,
  TeamNotFoundError,
} from "../../../github/errors.ts";
import { newTeamPrimitives } from "../handler.ts";

// The team the policies name, by its id. The double's team 7 is `platform`.
const TEAM_ID = "7";

/** The membership to leave the user with on the team. */
const onTeam = (role: TeamRole | null) => ({ teamId: TEAM_ID, role });

let github: ReturnType<typeof newGitHub>;
let connect: ReturnType<typeof vi.fn<ConnectGitHub>>;
let logs: ReturnType<typeof newRecordingLogger>;
let perimeter: ReturnType<typeof newTeamPrimitives>;

const NOT_ORG_MEMBER =
  "octocat isn't a member of acme, so P0 can't add them to platform. Add them to the org first.";

const MEMBERSHIP_PENDING =
  "octocat isn't a member of acme, so P0 can't add them to platform. GitHub left their membership of platform pending instead, and P0 couldn't remove it. Remove octocat from platform in the team's settings.";

const TARGET = { org: "acme", team: "platform", teamId: TEAM_ID, login: LOGIN };

const githubError = (status: number, githubMessages: string[]) =>
  new GitHubError({
    method: "PUT",
    path: "/organizations/1/team/7/memberships/octocat",
    status,
    githubMessages,
  });

const set = (role: TeamRole | null = "member") =>
  perimeter.setPoliciesForUser(CONTEXT, LOGIN, LOGIN, [onTeam(role)]);

beforeEach(() => {
  github = newGitHub();
  connect = vi.fn<ConnectGitHub>(async () => github);
  logs = newRecordingLogger();
  perimeter = newTeamPrimitives(logs.log, connect);
});

// The user primitives are shared with the `role` access, whose tests cover
// them. Only what the access passes them is checked here.
it("createUser refuses the grant, naming what it would have given", async () => {
  const data = await connectorError(() => perimeter.createUser(CONTEXT, LOGIN));

  expect(data.payload.reason).toBe("user_not_found");
  expect(data.message).toBe(
    "GitHub user octocat doesn't exist any more, so P0 can't give them a team membership in acme. Request access again with their current GitHub account."
  );
});

// A team's maintainers can rename it, and another team can take its old slug.
describe("setPoliciesForUser: the team", () => {
  it("is named by the slug it has now, read by the policy's id", async () => {
    github.fetchCurrentTeamSlug.mockResolvedValue("platform-renamed");
    github.verifyOrgMembership.mockResolvedValue(false);

    const data = await connectorError(() => set());

    expect(github.fetchCurrentTeamSlug).toHaveBeenCalledWith(TEAM_ID);
    // Its current slug is only for the message.
    expect(data.message).toBe(
      "octocat isn't a member of acme, so P0 can't add them to platform-renamed. Add them to the org first."
    );
  });

  // Both a grant and a revoke that restores a membership send a role.
  it.each(["member", "maintainer"] as const)(
    "fails a %s membership when it doesn't exist any more, changing nothing",
    async (role) => {
      github.fetchCurrentTeamSlug.mockResolvedValue(null);

      const data = await connectorError(() => set(role));

      expect(data.type).toBe("object_not_found");
      expect(data.payload).toEqual({
        query: "acme/7",
        org: "acme",
        teamId: TEAM_ID,
      });
      expect(data.message).toBe(
        "The team with id 7 doesn't exist in acme any more, so P0 couldn't add octocat to it. Request access to a team that does."
      );
      expect(github.putTeamMembership).not.toHaveBeenCalled();
      expect(github.removeTeamMembership).not.toHaveBeenCalled();
      expect(logs.warn).toHaveBeenCalledWith(
        "refused a membership of a team that doesn't exist any more"
      );
    }
  );

  // A deleted team has no members, so no membership of it can be left.
  it("removes nothing from a team that doesn't exist any more, and succeeds", async () => {
    github.fetchCurrentTeamSlug.mockResolvedValue(null);

    await expect(set(null)).resolves.toBeUndefined();

    expect(github.removeTeamMembership).not.toHaveBeenCalled();
    expect(github.putTeamMembership).not.toHaveBeenCalled();
    expect(logs.warn).not.toHaveBeenCalled();
  });

  it("maps a failed lookup through the GitHub error mapping", async () => {
    github.fetchCurrentTeamSlug.mockRejectedValue(githubError(502, ["boom"]));

    const data = await connectorError(() => set());

    expect(data.type).toBe("upstream_unavailable");
    expect(github.putTeamMembership).not.toHaveBeenCalled();
  });
});

// A grant sends the requested membership, and a revoke the one from before
// the grant. Both are set the same way.
describe("setPoliciesForUser: a membership", () => {
  it.each(["member", "maintainer"] as const)(
    "PUTs a %s membership for an org member, by the team's id",
    async (role) => {
      await set(role);

      expect(connect).toHaveBeenCalledWith(CONTEXT);
      expect(github.verifyOrgMembership).toHaveBeenCalledWith(LOGIN);
      expect(github.putTeamMembership).toHaveBeenCalledWith({
        teamId: TEAM_ID,
        login: LOGIN,
        role,
      });
      expect(github.removeTeamMembership).not.toHaveBeenCalled();
      expect(logs.info).toHaveBeenCalledWith("set the team membership");
    }
  );

  it("sets the membership without reading the one there now", async () => {
    await set();

    expect(github.fetchTeamMembership).not.toHaveBeenCalled();
  });

  it.each([
    ["no policy", []],
    ["two policies", [onTeam("member"), onTeam("maintainer")]],
  ])("refuses %s as a P0 bug", async (_case, policies) => {
    const data = await connectorError(() =>
      perimeter.setPoliciesForUser(CONTEXT, LOGIN, LOGIN, policies)
    );

    expect(data.type).toBe("unknown");
    expect(data.message).toBe(
      `Expected exactly 1 policy for a GitHub team membership, got ${policies.length}`
    );
    expect(connect).not.toHaveBeenCalled();
  });

  // GitHub would answer the PUT by inviting them to the org.
  describe("someone who isn't an org member", () => {
    beforeEach(() => {
      github.verifyOrgMembership.mockResolvedValue(false);
    });

    it("is refused without the PUT", async () => {
      const data = await connectorError(() => set());

      expect(github.putTeamMembership).not.toHaveBeenCalled();
      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({ reason: "not_org_member", ...TARGET });
      expect(data.message).toBe(NOT_ORG_MEMBER);
    });

    // An admin may have put the team on an invitation of their own.
    it("keeps any pending membership they have", async () => {
      await connectorError(() => set());

      expect(github.removeTeamMembership).not.toHaveBeenCalled();
    });
  });

  // They left the org after the membership check, so GitHub left the
  // membership pending.
  describe("a PUT that GitHub leaves pending", () => {
    beforeEach(() => {
      github.putTeamMembership.mockResolvedValue({ pending: true });
    });

    it("is taken back, and the grant fails", async () => {
      const data = await connectorError(() => set());

      expect(github.removeTeamMembership).toHaveBeenCalledWith({
        teamId: TEAM_ID,
        login: LOGIN,
      });
      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({ reason: "not_org_member", ...TARGET });
      expect(data.message).toBe(NOT_ORG_MEMBER);
    });

    it("says the membership is still pending when it can't be taken back", async () => {
      github.removeTeamMembership.mockRejectedValue(githubError(502, ["boom"]));

      const data = await connectorError(() => set());

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({ reason: "membership_pending", ...TARGET });
      expect(data.message).toBe(MEMBERSHIP_PENDING);
    });
  });

  it("says GitHub refused the change, quoting it and naming the usual cause", async () => {
    github.putTeamMembership.mockRejectedValue(
      new TeamChangeRefusedError(["Forbidden"])
    );

    const data = await connectorError(() => set());

    expect(data.type).toBe("validation_error");
    expect(data.payload).toEqual({
      reason: "team_change_refused",
      org: "acme",
      team: "platform",
      login: LOGIN,
    });
    expect(data.message).toBe(
      "GitHub refused to change who is on platform (Forbidden). If the team is synced with an identity provider group, change its members in the identity provider."
    );
  });

  // Only the client can tell which call a 403 came from.
  it("doesn't read a 403 from the membership check as a refused change", async () => {
    github.verifyOrgMembership.mockRejectedValue(
      githubError(403, ["Forbidden"])
    );

    const data = await connectorError(() => set());

    expect(data.type).toBe("insufficient_privileges");
    expect(github.putTeamMembership).not.toHaveBeenCalled();
  });

  it("maps any other failure through the GitHub error mapping", async () => {
    github.putTeamMembership.mockRejectedValue(githubError(502, ["boom"]));

    const data = await connectorError(() => set());

    expect(data.type).toBe("upstream_unavailable");
    expect(data.payload).toEqual({
      org: "acme",
      team: "platform",
      status: 502,
    });
  });
});

describe("setPoliciesForUser: no membership", () => {
  it("removes the membership by the team's id, without reading the one there now", async () => {
    await set(null);

    expect(github.removeTeamMembership).toHaveBeenCalledWith({
      teamId: TEAM_ID,
      login: LOGIN,
    });
    expect(github.putTeamMembership).not.toHaveBeenCalled();
    expect(github.fetchTeamMembership).not.toHaveBeenCalled();
    expect(logs.info).toHaveBeenCalledWith("removed the team membership");
  });

  it("fails when the membership can't be removed, naming the team", async () => {
    github.removeTeamMembership.mockRejectedValue(githubError(502, ["boom"]));

    const data = await connectorError(() => set(null));

    expect(data.type).toBe("upstream_unavailable");
    expect(data.payload).toMatchObject({ team: "platform" });
  });

  it("says GitHub refused the change", async () => {
    github.removeTeamMembership.mockRejectedValue(
      new TeamChangeRefusedError(["Forbidden"])
    );

    const data = await connectorError(() => set(null));

    expect(data.type).toBe("validation_error");
    expect(data.payload.reason).toBe("team_change_refused");
  });

  // P0 never looks for invitations, so a revoke is the removal alone, member
  // or not.
  it("removes a non-member's membership without checking the org", async () => {
    github.verifyOrgMembership.mockResolvedValue(false);

    await set(null);

    expect(github.removeTeamMembership).toHaveBeenCalledWith({
      teamId: TEAM_ID,
      login: LOGIN,
    });
    expect(github.verifyOrgMembership).not.toHaveBeenCalled();
  });
});

describe("list", () => {
  it("lists the org's teams, keyed by slug", async () => {
    github.listTeams.mockResolvedValue([
      { id: 7, nodeId: "T_7", slug: "platform", name: "Platform" },
      { id: 8, nodeId: "T_8", slug: "on-call", name: "On call" },
    ]);

    await expect(
      perimeter.list({ type: "team", context: CREDENTIALS })
    ).resolves.toEqual([
      { key: "platform", value: "Platform" },
      { key: "on-call", value: "On call" },
    ]);
    expect(connect).toHaveBeenCalledWith(CREDENTIALS);
  });

  it("reads the id behind a team's slug as one item, or none", async () => {
    const query = {
      type: "team-id" as const,
      context: CREDENTIALS,
      team: "Platform",
    };

    await expect(perimeter.list(query)).resolves.toEqual([]);

    github.fetchTeam.mockResolvedValue({ teamId: TEAM_ID, slug: "platform" });
    // The slug as GitHub spells it.
    await expect(perimeter.list(query)).resolves.toEqual([
      { key: TEAM_ID, value: "platform" },
    ]);
    expect(github.fetchTeam).toHaveBeenCalledWith("Platform");
  });

  it("reads a team membership by the team's id as one item, or none", async () => {
    const query = {
      type: "team-membership" as const,
      context: CREDENTIALS,
      teamId: TEAM_ID,
      login: LOGIN,
    };

    await expect(perimeter.list(query)).resolves.toEqual([]);

    github.fetchTeamMembership.mockResolvedValue("maintainer");
    await expect(perimeter.list(query)).resolves.toEqual([
      { key: "maintainer", value: "maintainer" },
    ]);
    expect(github.fetchTeamMembership).toHaveBeenCalledWith({
      teamId: TEAM_ID,
      login: LOGIN,
    });
  });

  it("maps a membership read of a team that doesn't exist to object_not_found", async () => {
    github.fetchTeamMembership.mockRejectedValue(
      new TeamNotFoundError(TEAM_ID)
    );

    const data = await connectorError(() =>
      perimeter.list({
        type: "team-membership",
        context: CREDENTIALS,
        teamId: TEAM_ID,
        login: LOGIN,
      })
    );

    expect(data.type).toBe("object_not_found");
    expect(data.message).toBe(
      "The team with id 7 doesn't exist in acme any more. Request access to a team that does."
    );
  });

  it("maps a failed team listing through the GitHub error mapping", async () => {
    github.listTeams.mockRejectedValue(githubError(502, ["boom"]));

    const data = await connectorError(() =>
      perimeter.list({ type: "team", context: CREDENTIALS })
    );

    expect(data.type).toBe("upstream_unavailable");
  });

  // The lookups it shares with the `role` access.
  it("answers the member and account lookups", async () => {
    github.findMemberLogin.mockResolvedValue(LOGIN);
    github.fetchAccount.mockResolvedValue({
      githubUserId: CONTEXT.githubUserId,
      login: LOGIN,
    });

    await expect(
      perimeter.list({
        type: "member",
        context: CREDENTIALS,
        email: "octocat@acme.com",
      })
    ).resolves.toEqual([{ key: LOGIN, value: LOGIN }]);
    await expect(
      perimeter.list({ type: "account", context: CREDENTIALS, login: LOGIN })
    ).resolves.toEqual([{ key: CONTEXT.githubUserId, value: LOGIN }]);
  });
});
