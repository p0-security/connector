import { ConnectorError, createLogger } from "@p0security/connector";
import { vi } from "vitest";

import type { GitHubClient } from "../client.ts";

export const LOGIN = "octocat";
export const GITHUB_USER_ID = "583231";

export const CREDENTIALS = {
  org: "acme",
  appId: "123456",
  privateKey: {
    manager: "aws" as const,
    secretId: "gh-app-key",
    region: "us-west-2",
  },
};

export const CONTEXT = {
  ...CREDENTIALS,
  requestId: "req-1",
  githubUserId: GITHUB_USER_ID,
};

/**
 * A silent logger whose child loggers are itself, so a test can read what any
 * of them logged.
 */
export const newRecordingLogger = () => {
  const log = createLogger();
  log.level = "silent";
  vi.spyOn(log, "child").mockReturnValue(log);
  return { log, info: vi.spyOn(log, "info"), warn: vi.spyOn(log, "warn") };
};

/** The data of the {@link ConnectorError} that `run` throws. */
export const connectorError = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    if (error instanceof ConnectorError) return error.data;
    throw error;
  }
  throw new Error("expected the call to throw");
};

/**
 * A {@link GitHubClient} double for an org member, {@link LOGIN}, with no
 * access of their own yet, in an org whose team 7 is `platform`.
 */
export const newGitHub = () => ({
  verifyAppJwt: vi.fn<GitHubClient["verifyAppJwt"]>(),
  fetchInstallation: vi.fn<GitHubClient["fetchInstallation"]>(),
  listRepositories: vi
    .fn<GitHubClient["listRepositories"]>()
    .mockResolvedValue([]),
  listCustomRoles: vi
    .fn<GitHubClient["listCustomRoles"]>()
    .mockResolvedValue([]),
  fetchBasePermission: vi
    .fn<GitHubClient["fetchBasePermission"]>()
    .mockResolvedValue(undefined),
  verifyOrgMembership: vi
    .fn<GitHubClient["verifyOrgMembership"]>()
    .mockResolvedValue(true),
  findMemberLogin: vi
    .fn<GitHubClient["findMemberLogin"]>()
    .mockResolvedValue(null),
  fetchDirectRole: vi
    .fn<GitHubClient["fetchDirectRole"]>()
    .mockResolvedValue(null),
  putRole: vi
    .fn<GitHubClient["putRole"]>()
    .mockResolvedValue({ invited: false, invitationId: undefined }),
  removeCollaborator: vi
    .fn<GitHubClient["removeCollaborator"]>()
    .mockResolvedValue(),
  listTeams: vi.fn<GitHubClient["listTeams"]>().mockResolvedValue([]),
  fetchTeam: vi.fn<GitHubClient["fetchTeam"]>().mockResolvedValue(null),
  fetchCurrentTeamSlug: vi
    .fn<GitHubClient["fetchCurrentTeamSlug"]>()
    .mockResolvedValue("platform"),
  fetchTeamMembership: vi
    .fn<GitHubClient["fetchTeamMembership"]>()
    .mockResolvedValue(null),
  putTeamMembership: vi
    .fn<GitHubClient["putTeamMembership"]>()
    .mockResolvedValue({ pending: false }),
  removeTeamMembership: vi
    .fn<GitHubClient["removeTeamMembership"]>()
    .mockResolvedValue(),
  fetchCurrentLogin: vi
    .fn<GitHubClient["fetchCurrentLogin"]>()
    .mockResolvedValue(LOGIN),
  fetchAccount: vi.fn<GitHubClient["fetchAccount"]>().mockResolvedValue(null),
  fetchRepository: vi
    .fn<GitHubClient["fetchRepository"]>()
    .mockResolvedValue(null),
  fetchBypassAllowances: vi
    .fn<GitHubClient["fetchBypassAllowances"]>()
    .mockResolvedValue({ users: [], teams: [], apps: [] }),
  setBypassAllowances: vi
    .fn<GitHubClient["setBypassAllowances"]>()
    .mockResolvedValue(),
  listProtectionPatterns: vi
    .fn<GitHubClient["listProtectionPatterns"]>()
    .mockResolvedValue([]),
});
