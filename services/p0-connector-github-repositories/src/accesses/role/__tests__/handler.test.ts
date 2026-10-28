import { ConnectorError, createLogger } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { GitHubError } from "../../../github/api.ts";
import type {
  ConnectGitHub,
  GitHubClient,
  RepositoryInvitations,
} from "../../../github/client.ts";
import {
  InstallationSuspendedError,
  MissingPermissionsError,
  RepositoryNotVisibleError,
} from "../../../github/errors.ts";
import { newRolePrimitives } from "../handler.ts";

const CREDENTIALS = {
  org: "acme",
  appId: "123456",
  privateKey: {
    manager: "aws" as const,
    secretId: "gh-app-key",
    region: "us-west-2",
  },
};

const LOGIN = "octocat";
const GITHUB_USER_ID = "583231";
const APP_BOT = "p0-acme[bot]";

const CONTEXT = {
  ...CREDENTIALS,
  requestId: "req-1",
  githubUserId: GITHUB_USER_ID,
};

/** The role to leave the user with on `api`. */
const onApi = (role: string | null) => ({ repo: "api", role });

/**
 * A silent logger whose child loggers are itself, so a test can read what any
 * of them logged.
 */
const newRecordingLogger = () => {
  const log = createLogger();
  log.level = "silent";
  vi.spyOn(log, "child").mockReturnValue(log);
  return { log, info: vi.spyOn(log, "info"), warn: vi.spyOn(log, "warn") };
};

const newInvitations = () => ({
  cancel: vi.fn<RepositoryInvitations["cancel"]>().mockResolvedValue(),
  findInvitationIds: vi
    .fn<RepositoryInvitations["findInvitationIds"]>()
    .mockResolvedValue([]),
});

const newGitHub = (invitations: RepositoryInvitations) => ({
  isAppJwtAccepted: vi.fn<GitHubClient["isAppJwtAccepted"]>(),
  findInstallation: vi.fn<GitHubClient["findInstallation"]>(),
  appBotLogin: vi.fn<GitHubClient["appBotLogin"]>().mockResolvedValue(APP_BOT),
  listRepositories: vi
    .fn<GitHubClient["listRepositories"]>()
    .mockResolvedValue([]),
  listCustomRoles: vi
    .fn<GitHubClient["listCustomRoles"]>()
    .mockResolvedValue([]),
  basePermission: vi
    .fn<GitHubClient["basePermission"]>()
    .mockResolvedValue(undefined),
  isMember: vi.fn<GitHubClient["isMember"]>().mockResolvedValue(true),
  findMemberLogin: vi
    .fn<GitHubClient["findMemberLogin"]>()
    .mockResolvedValue(null),
  readDirectRole: vi
    .fn<GitHubClient["readDirectRole"]>()
    .mockResolvedValue(null),
  putRole: vi
    .fn<GitHubClient["putRole"]>()
    .mockResolvedValue({ invited: false, invitationId: undefined }),
  removeCollaborator: vi
    .fn<GitHubClient["removeCollaborator"]>()
    .mockResolvedValue(),
  repositoryInvitations: vi
    .fn<GitHubClient["repositoryInvitations"]>()
    .mockResolvedValue(invitations),
  currentLogin: vi.fn<GitHubClient["currentLogin"]>().mockResolvedValue(LOGIN),
  findAccount: vi.fn<GitHubClient["findAccount"]>().mockResolvedValue(null),
  findRepository: vi
    .fn<GitHubClient["findRepository"]>()
    .mockResolvedValue(null),
});

let invitations: ReturnType<typeof newInvitations>;
let github: ReturnType<typeof newGitHub>;
let connect: ReturnType<typeof vi.fn<ConnectGitHub>>;
let logs: ReturnType<typeof newRecordingLogger>;
let perimeter: ReturnType<typeof newRolePrimitives>;

const connectorError = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    if (error instanceof ConnectorError) return error.data;
    throw error;
  }
  throw new Error("expected the call to throw");
};

const NOT_ORG_MEMBER =
  "octocat isn't a member of acme, so P0 can't give them a role on api. Add them to the org first.";

const INVITATION_PENDING =
  "octocat isn't a member of acme, so P0 can't give them a role on api. GitHub may have sent them an invitation to api instead, and P0 couldn't make sure it was cancelled. Check the repo's collaborator settings, and cancel any pending invitation from the GitHub App.";

const INVITATION_PENDING_AFTER_REVOKE =
  "octocat isn't a member of acme and has no direct role on api, but P0 couldn't make sure an invitation it sent to octocat for api was cancelled. Check the repo's collaborator settings, and cancel any pending invitation from the GitHub App.";

/** The lookup for the app's own invitations to `login`. */
const APP_INVITATIONS_TO = (login = LOGIN) => ({
  invitee: login,
  inviter: APP_BOT,
});

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
  invitations = newInvitations();
  github = newGitHub(invitations);
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
      expect(github.currentLogin).toHaveBeenCalledWith(GITHUB_USER_ID);
    });

    it("is the account's current login after a rename", async () => {
      github.currentLogin.mockResolvedValue("octocat-renamed");

      await expect(perimeter.getUser(CONTEXT, LOGIN)).resolves.toBe(
        "octocat-renamed"
      );
      expect(logs.info).toHaveBeenCalledWith(
        { currentLogin: "octocat-renamed" },
        "the account's login changed since the request; acting on its current login"
      );
    });

    it("doesn't log a login that differs only in case as renamed", async () => {
      github.currentLogin.mockResolvedValue("OctoCat");

      await expect(perimeter.getUser(CONTEXT, LOGIN)).resolves.toBe("OctoCat");
      expect(logs.info).not.toHaveBeenCalled();
    });

    // A null here would make P0 skip the revoke, leaving a non-member's role.
    it("doesn't check membership", async () => {
      github.isMember.mockResolvedValue(false);

      await expect(perimeter.getUser(CONTEXT, LOGIN)).resolves.toBe(LOGIN);
      expect(github.isMember).not.toHaveBeenCalled();
    });

    // P0's revoke then stops before changing anything, and its grant calls
    // createUser.
    it("is null when GitHub shows no account with the id", async () => {
      github.currentLogin.mockResolvedValue(null);

      await expect(perimeter.getUser(CONTEXT, LOGIN)).resolves.toBeNull();
      expect(logs.warn).toHaveBeenCalledWith(
        "GitHub shows no account with this id"
      );
    });

    it("maps a failed lookup through the GitHub error mapping", async () => {
      github.currentLogin.mockRejectedValue(githubError(502, ["boom"]));

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

  // The revoke already put the prior role back; a DELETE here would wipe it.
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
    expect(github.isMember).toHaveBeenCalledWith(LOGIN);
    expect(github.putRole).toHaveBeenCalledWith("api", LOGIN, "maintain");
    expect(github.isMember.mock.invocationCallOrder[0]).toBeLessThan(
      github.putRole.mock.invocationCallOrder[0]
    );
    // Checked again after the PUT, which a non-member can get through.
    expect(github.isMember).toHaveBeenCalledTimes(2);
    expect(github.putRole.mock.invocationCallOrder[0]).toBeLessThan(
      github.isMember.mock.invocationCallOrder[1]
    );
    expect(github.removeCollaborator).not.toHaveBeenCalled();
  });

  // There's no drift check: whatever is there now is replaced.
  it("sets the role without reading the one there now", async () => {
    github.readDirectRole.mockResolvedValue("admin");

    await grant("pull");

    expect(github.readDirectRole).not.toHaveBeenCalled();
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
      github.isMember.mockResolvedValueOnce(true).mockResolvedValue(false);
    });

    it("loses its direct role, and the call fails", async () => {
      const data = await connectorError(() => grant("admin"));

      expect(github.putRole).toHaveBeenCalledTimes(1);
      expect(github.putRole).toHaveBeenCalledWith("api", LOGIN, "admin");
      expect(github.removeCollaborator).toHaveBeenCalledWith("api", LOGIN);
      expect(invitations.findInvitationIds).toHaveBeenCalledWith(
        APP_INVITATIONS_TO()
      );
      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({
        reason: "not_org_member",
        org: "acme",
        repo: "api",
        login: LOGIN,
      });
      expect(data.message).toBe(NOT_ORG_MEMBER);
    });

    // An earlier attempt's PUT may have become an invitation it couldn't cancel.
    it("cancels the app's leftover invitation to them", async () => {
      invitations.findInvitationIds.mockResolvedValue([99]);

      const data = await connectorError(() => grant("admin"));

      expect(invitations.cancel).toHaveBeenCalledWith(99);
      expect(data.payload.reason).toBe("not_org_member");
    });

    it("says an invitation may be pending when the cancel fails", async () => {
      invitations.findInvitationIds.mockResolvedValue([99]);
      invitations.cancel.mockRejectedValue(githubError(502, ["boom"]));

      const data = await connectorError(() => grant("admin"));

      expect(github.removeCollaborator).toHaveBeenCalledWith("api", LOGIN);
      expect(data.payload.reason).toBe("invitation_pending");
      expect(data.message).toBe(INVITATION_PENDING);
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
    github.isMember.mockResolvedValue(false);
    github.putRole.mockResolvedValue(put);

    const data = await connectorError(() => grant());

    expect(github.putRole).not.toHaveBeenCalled();
    expect(invitations.findInvitationIds).toHaveBeenCalledWith(
      APP_INVITATIONS_TO()
    );
    expect(invitations.cancel).not.toHaveBeenCalled();
    expect(data.type).toBe("validation_error");
    expect(data.payload).toEqual({
      reason: "not_org_member",
      org: "acme",
      repo: "api",
      login: LOGIN,
    });
    expect(data.message).toBe(NOT_ORG_MEMBER);
  });

  // An earlier attempt's PUT became an invitation it couldn't cancel, and P0
  // retried the grant.
  it("cancels the app's leftover invitation for a non-member, then refuses", async () => {
    github.isMember.mockResolvedValue(false);
    invitations.findInvitationIds.mockResolvedValue([99]);

    const data = await connectorError(() => grant());

    expect(github.repositoryInvitations).toHaveBeenCalledWith("api");
    expect(invitations.cancel).toHaveBeenCalledWith(99);
    expect(github.putRole).not.toHaveBeenCalled();
    expect(data.type).toBe("validation_error");
    expect(data.payload.reason).toBe("not_org_member");
    expect(data.message).toBe(NOT_ORG_MEMBER);
  });

  it.each([
    {
      how: "cancelling the leftover invitation fails",
      setup: () => {
        invitations.findInvitationIds.mockResolvedValue([99]);
        invitations.cancel.mockRejectedValue(githubError(502, ["boom"]));
      },
    },
    {
      how: "the invitations can't be read",
      setup: () => {
        invitations.findInvitationIds.mockRejectedValue(
          githubError(502, ["boom"])
        );
      },
    },
  ])(
    "refuses a non-member visibly, saying an invitation may be pending, when $how",
    async ({ setup }) => {
      github.isMember.mockResolvedValue(false);
      setup();

      const data = await connectorError(() => grant());

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({
        reason: "invitation_pending",
        org: "acme",
        repo: "api",
        login: LOGIN,
      });
      expect(data.message).toBe(INVITATION_PENDING);
    }
  );

  // Nothing suggests an invitation exists until the search has started, so a
  // failure getting there keeps its own reason: an invitation_pending would
  // never clear on a retry.
  it.each([
    {
      how: "the app lost administration: write",
      setup: () =>
        github.repositoryInvitations.mockRejectedValue(
          new MissingPermissionsError(["administration=write"])
        ),
      type: "insufficient_privileges",
      reason: undefined,
      message:
        "The GitHub App for acme is missing administration=write. Grant it in the app's settings and accept the update on the installation.",
    },
    {
      how: "the installation is suspended",
      setup: () =>
        github.repositoryInvitations.mockRejectedValue(
          new InstallationSuspendedError()
        ),
      type: "insufficient_privileges",
      reason: "installation_suspended",
      message:
        "The GitHub App's installation on acme is suspended. Ask an owner of acme to unsuspend it in the org's GitHub App settings, then retry.",
    },
    {
      how: "GitHub refuses the token as suspended",
      setup: () =>
        github.repositoryInvitations.mockRejectedValue(
          githubError(403, ["This installation has been suspended"])
        ),
      type: "insufficient_privileges",
      reason: "installation_suspended",
      message: undefined,
    },
    {
      how: "GitHub rejects the credentials minting the token",
      setup: () =>
        github.repositoryInvitations.mockRejectedValue(
          githubError(401, ["Bad credentials"])
        ),
      type: "insufficient_privileges",
      reason: "credentials_rejected",
      message: undefined,
    },
    {
      how: "GitHub rejects the credentials reading the app's slug",
      setup: () =>
        github.appBotLogin.mockRejectedValue(
          githubError(401, ["Bad credentials"])
        ),
      type: "insufficient_privileges",
      reason: "credentials_rejected",
      message: undefined,
    },
    {
      how: "GitHub can't answer for the app's slug",
      setup: () =>
        github.appBotLogin.mockRejectedValue(githubError(502, ["boom"])),
      type: "upstream_unavailable",
      reason: undefined,
      message: undefined,
    },
  ])(
    "refuses a non-member with the real cause when $how before the search starts",
    async ({ setup, type, reason, message }) => {
      github.isMember.mockResolvedValue(false);
      setup();

      const data = await connectorError(() => grant());

      expect(data.type).toBe(type);
      expect(data.payload.reason).toBe(reason);
      if (message !== undefined) expect(data.message).toBe(message);
      expect(invitations.findInvitationIds).not.toHaveBeenCalled();
      expect(github.putRole).not.toHaveBeenCalled();
    }
  );

  describe("an invitation from a user who left the org after the membership check", () => {
    it("is cancelled by its id, and the grant fails", async () => {
      github.isMember.mockResolvedValueOnce(true).mockResolvedValue(false);
      github.putRole.mockResolvedValue({ invited: true, invitationId: 99 });

      const data = await connectorError(() => grant());

      expect(invitations.cancel).toHaveBeenCalledWith(99);
      expect(invitations.findInvitationIds).not.toHaveBeenCalled();
      // No role was set, so there's nothing to take back.
      expect(github.putRole).toHaveBeenCalledTimes(1);
      expect(github.removeCollaborator).not.toHaveBeenCalled();
      expect(data.type).toBe("validation_error");
      expect(data.payload.reason).toBe("not_org_member");
      expect(data.message).toBe(NOT_ORG_MEMBER);
    });

    it("is looked up and cancelled when GitHub doesn't return its id", async () => {
      github.putRole.mockResolvedValue({
        invited: true,
        invitationId: undefined,
      });
      invitations.findInvitationIds.mockResolvedValue([7]);

      const data = await connectorError(() => grant());

      expect(invitations.findInvitationIds).toHaveBeenCalledWith(
        APP_INVITATIONS_TO()
      );
      expect(invitations.cancel).toHaveBeenCalledWith(7);
      expect(data.payload.reason).toBe("not_org_member");
    });

    it("is looked up and cancelled again, with the same token, when cancelling by id fails", async () => {
      github.putRole.mockResolvedValue({ invited: true, invitationId: 99 });
      invitations.cancel.mockRejectedValueOnce(githubError(502, ["boom"]));
      invitations.findInvitationIds.mockResolvedValue([99]);

      const data = await connectorError(() => grant());

      expect(github.repositoryInvitations).toHaveBeenCalledTimes(1);
      expect(invitations.cancel).toHaveBeenCalledTimes(2);
      expect(invitations.cancel).toHaveBeenLastCalledWith(99);
      expect(data.payload.reason).toBe("not_org_member");
    });

    it.each([
      {
        how: "both cancels fail",
        setup: () => {
          github.putRole.mockResolvedValue({ invited: true, invitationId: 99 });
          invitations.cancel.mockRejectedValue(githubError(502, ["boom"]));
          invitations.findInvitationIds.mockResolvedValue([99]);
        },
        invitationId: 99,
      },
      {
        how: "the lookup fails",
        setup: () => {
          github.putRole.mockResolvedValue({ invited: true, invitationId: 99 });
          invitations.cancel.mockRejectedValue(githubError(502, ["boom"]));
          invitations.findInvitationIds.mockRejectedValue(
            githubError(502, ["boom"])
          );
        },
        invitationId: 99,
      },
      // GitHub said it sent one, so even a failure before the search counts.
      {
        how: "the write token can't be minted",
        setup: () => {
          github.putRole.mockResolvedValue({ invited: true, invitationId: 99 });
          github.repositoryInvitations.mockRejectedValue(
            new MissingPermissionsError(["administration=write"])
          );
        },
        invitationId: 99,
      },
      {
        how: "the cancel by id fails and the app's slug can't be read",
        setup: () => {
          github.putRole.mockResolvedValue({ invited: true, invitationId: 99 });
          invitations.cancel.mockRejectedValue(githubError(502, ["boom"]));
          github.appBotLogin.mockRejectedValue(
            githubError(401, ["Bad credentials"])
          );
        },
        invitationId: 99,
      },
      {
        how: "there's no id and the lookup finds nothing",
        setup: () => {
          github.putRole.mockResolvedValue({
            invited: true,
            invitationId: undefined,
          });
        },
        invitationId: undefined,
      },
    ])(
      "fails visibly, saying one may be pending, when $how",
      async ({ setup, invitationId }) => {
        setup();

        const data = await connectorError(() => grant());

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
  });

  it("refuses a role below the org's base permission, naming the base", async () => {
    github.putRole.mockRejectedValue(
      githubError(422, [
        "Validation Failed",
        "Cannot assign member permission of read",
      ])
    );
    github.basePermission.mockResolvedValue("write");

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
    github.basePermission.mockRejectedValue(githubError(403, ["Forbidden"]));

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
    expect(github.readDirectRole).not.toHaveBeenCalled();
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
    github.isMember.mockResolvedValue(false);
    github.removeCollaborator.mockRejectedValue(githubError(502, ["boom"]));

    const data = await connectorError(() => remove());

    expect(data.type).toBe("upstream_unavailable");
    expect(github.repositoryInvitations).not.toHaveBeenCalled();
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

  // P0 never invites anyone, so a revoke never ends with the app's invitation
  // still pending for someone outside the org. P0's rollback of a grant whose
  // PUT became an invitation can end here.
  describe("the app's invitations to someone no longer in the org", () => {
    beforeEach(() => {
      github.isMember.mockResolvedValue(false);
      invitations.findInvitationIds.mockResolvedValue([99]);
    });

    it("are cancelled after the direct role is removed", async () => {
      await remove();

      expect(github.removeCollaborator).toHaveBeenCalledWith("api", LOGIN);
      expect(github.repositoryInvitations).toHaveBeenCalledWith("api");
      expect(invitations.findInvitationIds).toHaveBeenCalledWith(
        APP_INVITATIONS_TO()
      );
      expect(invitations.cancel).toHaveBeenCalledWith(99);
      // The elevated role goes first.
      expect(
        github.removeCollaborator.mock.invocationCallOrder[0]
      ).toBeLessThan(github.repositoryInvitations.mock.invocationCallOrder[0]);
    });

    it.each([
      {
        how: "they can't be cancelled",
        setup: () =>
          invitations.cancel.mockRejectedValue(githubError(502, ["boom"])),
      },
      {
        how: "they can't be read",
        setup: () =>
          invitations.findInvitationIds.mockRejectedValue(
            githubError(502, ["boom"])
          ),
      },
    ])(
      "fail the call, saying one may be pending, when $how",
      async ({ setup }) => {
        setup();

        const data = await connectorError(() => remove());

        expect(data.type).toBe("validation_error");
        expect(data.payload).toEqual({
          reason: "invitation_pending",
          org: "acme",
          repo: "api",
          login: LOGIN,
        });
        expect(data.message).toBe(INVITATION_PENDING_AFTER_REVOKE);
        expect(github.removeCollaborator).toHaveBeenCalledTimes(1);
      }
    );

    it("fail the call with the real cause when the search can't start", async () => {
      github.repositoryInvitations.mockRejectedValue(
        new MissingPermissionsError(["administration=write"])
      );

      const data = await connectorError(() => remove());

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({
        org: "acme",
        permission: "administration=write",
      });
    });

    it("are cancelled by a retry after the cancel failed", async () => {
      invitations.cancel
        .mockRejectedValueOnce(githubError(502, ["boom"]))
        .mockResolvedValueOnce();

      await connectorError(() => remove());
      await remove();

      expect(invitations.cancel).toHaveBeenCalledTimes(2);
    });

    it("aren't looked for when the user is still a member", async () => {
      github.isMember.mockResolvedValue(true);

      await remove();

      expect(github.isMember).toHaveBeenCalledWith(LOGIN);
      expect(github.repositoryInvitations).not.toHaveBeenCalled();
    });
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
    github.readDirectRole.mockResolvedValue("push");
    await expect(perimeter.list(query)).resolves.toEqual([
      { key: "push", value: "push" },
    ]);

    github.readDirectRole.mockResolvedValue(null);
    await expect(perimeter.list(query)).resolves.toEqual([]);
  });

  // At request time nothing has changed yet, so the copy is for the requester.
  it("maps a direct-role read of a repo the app can't see to object_not_found", async () => {
    github.readDirectRole.mockRejectedValue(
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
    github.findAccount.mockResolvedValue({
      githubUserId: GITHUB_USER_ID,
      login: "OctoCat",
    });
    await expect(perimeter.list(query)).resolves.toEqual([
      { key: GITHUB_USER_ID, value: "OctoCat" },
    ]);
    expect(github.findAccount).toHaveBeenCalledWith(LOGIN);

    github.findAccount.mockResolvedValue(null);
    await expect(perimeter.list(query)).resolves.toEqual([]);
  });

  it("maps a failed account lookup through the GitHub error mapping", async () => {
    github.findAccount.mockRejectedValue(githubError(502, ["boom"]));

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
    github.findRepository.mockResolvedValue({
      repositoryId: "1296269",
      name: "api",
    });
    await expect(perimeter.list(query)).resolves.toEqual([
      { key: "1296269", value: "api" },
    ]);
    expect(github.findRepository).toHaveBeenCalledWith("old-api");

    github.findRepository.mockResolvedValue(null);
    await expect(perimeter.list(query)).resolves.toEqual([]);
  });

  it("maps a failed repository id lookup through the GitHub error mapping", async () => {
    github.findRepository.mockRejectedValue(githubError(502, ["boom"]));

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
