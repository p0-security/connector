import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  CONTEXT,
  CREDENTIALS,
  GITHUB_USER_ID,
  LOGIN,
  connectorError,
  newGitHub,
  newRecordingLogger,
} from "../../../github/__tests__/doubles.ts";
import { GitHubError } from "../../../github/api.ts";
import type { ConnectGitHub } from "../../../github/client.ts";
import { RepositoryNotVisibleError } from "../../../github/errors.ts";
import { newRolePrimitives } from "../handler.ts";

/** The role to leave the user with on `api`. */
const onApi = (role: string | null) => ({ repo: "api", role });

let github: ReturnType<typeof newGitHub>;
let connect: ReturnType<typeof vi.fn<ConnectGitHub>>;
let logs: ReturnType<typeof newRecordingLogger>;
let perimeter: ReturnType<typeof newRolePrimitives>;

const NOT_ORG_MEMBER =
  "octocat isn't a member of acme, so P0 can't give them a role on api. Add them to the org first.";

const INVITATION_PENDING =
  "octocat isn't a member of acme, so P0 can't give them a role on api. GitHub sent octocat an invitation to api. Cancel it in the repo's collaborator settings, then add octocat to acme and request again.";

const githubError = (
  status: number,
  githubMessages: string[],
  extra: { acceptedPermissions?: string } = {}
) =>
  new GitHubError({
    method: "PUT",
    path: "/repos/acme/api/collaborators/octocat",
    status,
    githubMessages,
    ...extra,
  });

beforeEach(() => {
  github = newGitHub();
  connect = vi.fn<ConnectGitHub>(async () => github);
  logs = newRecordingLogger();
  perimeter = newRolePrimitives(logs.log, connect);
});

describe("user primitives", () => {
  it("validation has no namespace to check", () => {
    expect(perimeter.validation(CONTEXT)).toEqual({ user: null });
  });

  // The role moves with the account when its owner renames it, and the old
  // login can then belong to someone else entirely.
  describe("getUser", () => {
    it("is the login of the context's account, looked up by its id", async () => {
      await expect(perimeter.getUser(CONTEXT, LOGIN)).resolves.toBe(LOGIN);
      expect(connect).toHaveBeenCalledWith(CONTEXT);
      expect(github.fetchCurrentLogin).toHaveBeenCalledWith(GITHUB_USER_ID);
    });

    it("is the account's current login after a rename", async () => {
      github.fetchCurrentLogin.mockResolvedValue("octocat-renamed");

      await expect(perimeter.getUser(CONTEXT, LOGIN)).resolves.toBe(
        "octocat-renamed"
      );
      expect(logs.info).toHaveBeenCalledWith(
        { currentLogin: "octocat-renamed" },
        "the account's login changed since the request, so P0 acts on its current login"
      );
    });

    it("doesn't log a login that differs only in case as renamed", async () => {
      github.fetchCurrentLogin.mockResolvedValue("OctoCat");

      await expect(perimeter.getUser(CONTEXT, LOGIN)).resolves.toBe("OctoCat");
      expect(logs.info).not.toHaveBeenCalled();
    });

    // A null here would make P0 skip the revoke, leaving a non-member's role.
    it("doesn't check membership", async () => {
      github.verifyOrgMembership.mockResolvedValue(false);

      await expect(perimeter.getUser(CONTEXT, LOGIN)).resolves.toBe(LOGIN);
      expect(github.verifyOrgMembership).not.toHaveBeenCalled();
    });

    // P0's revoke then stops before changing anything, and its grant calls
    // createUser.
    it("is null when GitHub shows no account with the id", async () => {
      github.fetchCurrentLogin.mockResolvedValue(null);

      await expect(perimeter.getUser(CONTEXT, LOGIN)).resolves.toBeNull();
      expect(logs.warn).toHaveBeenCalledWith(
        "GitHub shows no account with this id"
      );
    });

    it("maps a failed lookup through the GitHub error mapping", async () => {
      github.fetchCurrentLogin.mockRejectedValue(githubError(502, ["boom"]));

      const data = await connectorError(() =>
        perimeter.getUser(CONTEXT, LOGIN)
      );

      expect(data.type).toBe("upstream_unavailable");
    });
  });

  it("createUser refuses the grant, saying the user doesn't exist", async () => {
    const data = await connectorError(() =>
      perimeter.createUser(CONTEXT, LOGIN)
    );

    expect(data.type).toBe("validation_error");
    expect(data.payload).toEqual({
      reason: "user_not_found",
      org: "acme",
      login: LOGIN,
      githubUserId: GITHUB_USER_ID,
    });
    expect(data.message).toBe(
      "GitHub user octocat doesn't exist any more, so P0 can't give them a role in acme. Request access again with their current GitHub account."
    );
    expect(connect).not.toHaveBeenCalled();
  });

  // The revoke already put the prior role back, and a DELETE here would wipe it.
  it("deleteUser changes nothing", async () => {
    await perimeter.deleteUser(CONTEXT, LOGIN, LOGIN);
    expect(connect).not.toHaveBeenCalled();
  });
});

// A grant sends the requested role, and a revoke the role from before the
// grant. Both are set the same way.
describe("setPoliciesForUser: a role", () => {
  const grant = (role = "push") =>
    perimeter.setPoliciesForUser(CONTEXT, LOGIN, LOGIN, [onApi(role)]);

  it("PUTs the role for an org member", async () => {
    await grant("maintain");
    expect(github.verifyOrgMembership).toHaveBeenCalledWith(LOGIN);
    expect(github.putRole).toHaveBeenCalledWith("api", LOGIN, "maintain");
    expect(github.verifyOrgMembership.mock.invocationCallOrder[0]).toBeLessThan(
      github.putRole.mock.invocationCallOrder[0]
    );
    // Checked again after the PUT, which a non-member can get through.
    expect(github.verifyOrgMembership).toHaveBeenCalledTimes(2);
    expect(github.putRole.mock.invocationCallOrder[0]).toBeLessThan(
      github.verifyOrgMembership.mock.invocationCallOrder[1]
    );
    expect(github.removeCollaborator).not.toHaveBeenCalled();
  });

  // There's no drift check: whatever is there now is replaced.
  it("sets the role without reading the one there now", async () => {
    github.fetchDirectRole.mockResolvedValue("admin");

    await grant("pull");

    expect(github.fetchDirectRole).not.toHaveBeenCalled();
    expect(github.putRole).toHaveBeenCalledWith("api", LOGIN, "pull");
  });

  it("acts on the repo the policy names", async () => {
    await perimeter.setPoliciesForUser(CONTEXT, LOGIN, LOGIN, [
      { repo: "web", role: "push" },
    ]);

    expect(github.putRole).toHaveBeenCalledWith("web", LOGIN, "push");
  });

  // A 204 for an existing outside collaborator who left the org after the
  // membership check: the role went through, so it's taken back.
  describe("a role set for a user who left the org after the membership check", () => {
    beforeEach(() => {
      github.verifyOrgMembership
        .mockResolvedValueOnce(true)
        .mockResolvedValue(false);
    });

    it("loses its direct role, and the call fails", async () => {
      const data = await connectorError(() => grant("admin"));

      expect(github.putRole).toHaveBeenCalledTimes(1);
      expect(github.putRole).toHaveBeenCalledWith("api", LOGIN, "admin");
      expect(github.removeCollaborator).toHaveBeenCalledWith("api", LOGIN);
      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({
        reason: "not_org_member",
        org: "acme",
        repo: "api",
        login: LOGIN,
      });
      expect(data.message).toBe(NOT_ORG_MEMBER);
    });

    it("fails the grant when the role can't be taken back", async () => {
      github.removeCollaborator.mockRejectedValue(githubError(502, ["boom"]));

      const data = await connectorError(() => grant("admin"));

      expect(data.type).toBe("upstream_unavailable");
    });
  });

  // GitHub would invite the first and quietly set the role for the second.
  it.each([
    {
      who: "someone outside the org",
      put: { invited: true, invitationId: 99 },
    },
    {
      who: "an existing outside collaborator",
      put: { invited: false, invitationId: undefined },
    },
  ])("refuses $who before any PUT", async ({ put }) => {
    github.verifyOrgMembership.mockResolvedValue(false);
    github.putRole.mockResolvedValue(put);

    const data = await connectorError(() => grant());

    expect(github.putRole).not.toHaveBeenCalled();
    expect(data.type).toBe("validation_error");
    expect(data.payload).toEqual({
      reason: "not_org_member",
      org: "acme",
      repo: "api",
      login: LOGIN,
    });
    expect(data.message).toBe(NOT_ORG_MEMBER);
  });

  // P0 makes no invitation call, so the invitation is left for the admin.
  it.each([{ invitationId: 99 }, { invitationId: undefined }])(
    "fails the grant on an invitation for a user who left the org after the membership check (id $invitationId)",
    async ({ invitationId }) => {
      github.verifyOrgMembership
        .mockResolvedValueOnce(true)
        .mockResolvedValue(false);
      github.putRole.mockResolvedValue({ invited: true, invitationId });

      const data = await connectorError(() => grant());

      // No role was set, so there's nothing to take back.
      expect(github.putRole).toHaveBeenCalledTimes(1);
      expect(github.removeCollaborator).not.toHaveBeenCalled();
      // `validation_error` is the type whose message P0 shows.
      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({
        reason: "invitation_pending",
        org: "acme",
        repo: "api",
        login: LOGIN,
        ...(invitationId !== undefined ? { invitationId } : {}),
      });
      expect(data.message).toBe(INVITATION_PENDING);
    }
  );

  it("refuses a role below the org's base permission, naming the base", async () => {
    github.putRole.mockRejectedValue(
      githubError(422, [
        "Validation Failed",
        "Cannot assign member permission of read",
      ])
    );
    github.fetchBasePermission.mockResolvedValue("write");

    const data = await connectorError(() => grant("pull"));

    expect(data.type).toBe("validation_error");
    expect(data.payload.reason).toBe("below_base_permission");
    expect(data.payload.basePermission).toBe("write");
    expect(data.message).toBe(
      "acme's base permission is Write, which is higher than Read. Request Write or higher."
    );
  });

  it("still names the floor when GitHub won't show the base permission", async () => {
    github.putRole.mockRejectedValue(githubError(422, ["Cannot assign x"]));
    github.fetchBasePermission.mockRejectedValue(
      githubError(403, ["Forbidden"])
    );

    const data = await connectorError(() => grant("pull"));

    expect(data.payload.reason).toBe("below_base_permission");
    expect(data.message).toBe(
      "acme's base permission is higher than Read. Request a role at or above the org's base permission."
    );
  });

  it("reads the floor from a 403 as well as a 422", async () => {
    github.putRole.mockRejectedValue(
      githubError(403, ["Cannot assign member permission of read"])
    );

    const data = await connectorError(() => grant("pull"));

    expect(data.type).toBe("validation_error");
    expect(data.payload.reason).toBe("below_base_permission");
  });

  it("maps a 403 to insufficient_privileges, naming the missing permission", async () => {
    github.putRole.mockRejectedValue(
      githubError(403, ["Resource not accessible by integration"], {
        acceptedPermissions: "administration=write",
      })
    );

    const data = await connectorError(() => grant());

    expect(data.type).toBe("insufficient_privileges");
    expect(data.message).toBe(
      "The GitHub App for acme is missing administration=write. Grant it in the app's settings and accept the update on the installation."
    );
  });

  it.each([
    [429, "rate_limited"],
    [502, "upstream_unavailable"],
  ])("maps a %d to %s", async (status, type) => {
    github.putRole.mockRejectedValue(githubError(status, ["nope"]));
    const data = await connectorError(() => grant());
    expect(data.type).toBe(type);
  });

  it("fails when the repo left the app's repository selection", async () => {
    github.putRole.mockRejectedValue(new RepositoryNotVisibleError("api"));

    const data = await connectorError(() => grant());

    expect(data.type).toBe("object_not_found");
    expect(data.payload.query).toBe("acme/api");
    expect(data.message).toBe(
      "api isn't in the GitHub App's repository selection, so P0 couldn't change octocat's role. Add the repo back to the app and retry, or change the role in GitHub."
    );
  });

  it.each([
    { what: "no policy", policies: [] },
    { what: "more than one policy", policies: [onApi("push"), onApi(null)] },
  ])("refuses $what, as a P0 bug", async ({ policies }) => {
    const data = await connectorError(() =>
      perimeter.setPoliciesForUser(CONTEXT, LOGIN, LOGIN, policies)
    );

    expect(data.type).toBe("unknown");
    expect(data.payload).toEqual({
      requestId: "req-1",
      nPolicies: policies.length,
    });
    expect(connect).not.toHaveBeenCalled();
  });
});

// A revoke to someone who had no direct role before the grant.
describe("setPoliciesForUser: no role", () => {
  const remove = () =>
    perimeter.setPoliciesForUser(CONTEXT, LOGIN, LOGIN, [onApi(null)]);

  it("removes the direct role, without reading the one there now", async () => {
    await remove();

    expect(github.removeCollaborator).toHaveBeenCalledWith("api", LOGIN);
    expect(github.fetchDirectRole).not.toHaveBeenCalled();
    expect(github.putRole).not.toHaveBeenCalled();
  });

  // P0 runs every checked step twice in dev and stage, and retries a step
  // whose response was lost.
  it("succeeds again when run a second time", async () => {
    await remove();
    await remove();

    expect(github.removeCollaborator).toHaveBeenCalledTimes(2);
  });

  it("fails when the direct role can't be removed", async () => {
    github.verifyOrgMembership.mockResolvedValue(false);
    github.removeCollaborator.mockRejectedValue(githubError(502, ["boom"]));

    const data = await connectorError(() => remove());

    expect(data.type).toBe("upstream_unavailable");
  });

  it("fails when the repo left the app's repository selection", async () => {
    github.removeCollaborator.mockRejectedValue(
      new RepositoryNotVisibleError("api")
    );

    const data = await connectorError(() => remove());

    expect(data.type).toBe("object_not_found");
    expect(data.message).toBe(
      "api isn't in the GitHub App's repository selection, so P0 couldn't change octocat's role. Add the repo back to the app and retry, or change the role in GitHub."
    );
  });

  // A revoke is the removal alone, member or not.
  it("removes a non-member's direct role", async () => {
    github.verifyOrgMembership.mockResolvedValue(false);

    await remove();

    expect(github.removeCollaborator).toHaveBeenCalledWith("api", LOGIN);
    expect(github.verifyOrgMembership).not.toHaveBeenCalled();
  });
});

describe("list", () => {
  it("lists the installation's repositories by bare name", async () => {
    github.listRepositories.mockResolvedValue([
      { name: "api", full_name: "acme/api" },
      { name: "web", full_name: "acme/web" },
    ]);

    await expect(
      perimeter.list({ context: CREDENTIALS, type: "repository" })
    ).resolves.toEqual([
      { key: "api", value: "api" },
      { key: "web", value: "web" },
    ]);
    expect(connect).toHaveBeenCalledWith(CREDENTIALS);
  });

  it("lists built-in roles, keyed by their PUT value, then custom roles", async () => {
    github.listCustomRoles.mockResolvedValue(["Labeler"]);

    await expect(
      perimeter.list({ context: CREDENTIALS, type: "role" })
    ).resolves.toEqual([
      { key: "pull", value: "Read" },
      { key: "triage", value: "Triage" },
      { key: "triage_plus", value: "Triage Plus" },
      { key: "push", value: "Write" },
      { key: "maintain", value: "Maintain" },
      { key: "admin", value: "Admin" },
      { key: "Labeler", value: "Labeler" },
    ]);
  });

  it("lists only built-in roles when custom roles can't be read", async () => {
    github.listCustomRoles.mockRejectedValue(githubError(404, ["Not Found"]));

    const roles = await perimeter.list({ context: CREDENTIALS, type: "role" });

    expect(roles.map(({ key }) => key)).toEqual([
      "pull",
      "triage",
      "triage_plus",
      "push",
      "maintain",
      "admin",
    ]);
  });

  it("reads a direct role as one item, or none", async () => {
    const query = {
      context: CREDENTIALS,
      type: "direct-role" as const,
      repo: "api",
      login: LOGIN,
    };
    github.fetchDirectRole.mockResolvedValue("push");
    await expect(perimeter.list(query)).resolves.toEqual([
      { key: "push", value: "push" },
    ]);

    github.fetchDirectRole.mockResolvedValue(null);
    await expect(perimeter.list(query)).resolves.toEqual([]);
  });

  // At request time nothing has changed yet, so the copy is for the requester.
  it("maps a direct-role read of a repo the app can't see to object_not_found", async () => {
    github.fetchDirectRole.mockRejectedValue(
      new RepositoryNotVisibleError("api")
    );

    const data = await connectorError(() =>
      perimeter.list({
        context: CREDENTIALS,
        type: "direct-role",
        repo: "api",
        login: LOGIN,
      })
    );

    expect(data.type).toBe("object_not_found");
    expect(data.payload.query).toBe("acme/api");
    expect(data.message).toBe(
      "api isn't in the GitHub App's repository selection. Ask your GitHub admin to add it to the app."
    );
  });

  it("matches an email to a member's login, or nothing", async () => {
    const query = {
      context: CREDENTIALS,
      type: "member" as const,
      email: "octocat@acme.com",
    };
    github.findMemberLogin.mockResolvedValue(LOGIN);
    await expect(perimeter.list(query)).resolves.toEqual([
      { key: LOGIN, value: LOGIN },
    ]);
    expect(github.findMemberLogin).toHaveBeenCalledWith("octocat@acme.com");

    github.findMemberLogin.mockResolvedValue(null);
    await expect(perimeter.list(query)).resolves.toEqual([]);
  });

  it("reads the GitHub user id behind a login as one item, or none", async () => {
    const query = {
      context: CREDENTIALS,
      type: "account" as const,
      login: LOGIN,
    };
    github.fetchAccount.mockResolvedValue({
      githubUserId: GITHUB_USER_ID,
      login: "OctoCat",
    });
    await expect(perimeter.list(query)).resolves.toEqual([
      { key: GITHUB_USER_ID, value: "OctoCat" },
    ]);
    expect(github.fetchAccount).toHaveBeenCalledWith(LOGIN);

    github.fetchAccount.mockResolvedValue(null);
    await expect(perimeter.list(query)).resolves.toEqual([]);
  });

  it("maps a failed account lookup through the GitHub error mapping", async () => {
    github.fetchAccount.mockRejectedValue(githubError(502, ["boom"]));

    const data = await connectorError(() =>
      perimeter.list({ context: CREDENTIALS, type: "account", login: LOGIN })
    );

    expect(data.type).toBe("upstream_unavailable");
  });

  it("reads the id behind a repository's name as one item, or none", async () => {
    const query = {
      context: CREDENTIALS,
      type: "repository-id" as const,
      repo: "old-api",
    };
    github.fetchRepository.mockResolvedValue({
      repositoryId: "1296269",
      name: "api",
    });
    await expect(perimeter.list(query)).resolves.toEqual([
      { key: "1296269", value: "api" },
    ]);
    expect(github.fetchRepository).toHaveBeenCalledWith("old-api");

    github.fetchRepository.mockResolvedValue(null);
    await expect(perimeter.list(query)).resolves.toEqual([]);
  });

  it("maps a failed repository id lookup through the GitHub error mapping", async () => {
    github.fetchRepository.mockRejectedValue(githubError(502, ["boom"]));

    const data = await connectorError(() =>
      perimeter.list({
        context: CREDENTIALS,
        type: "repository-id",
        repo: "api",
      })
    );

    expect(data.type).toBe("upstream_unavailable");
  });
});
