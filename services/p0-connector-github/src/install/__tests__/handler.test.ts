import { describe, expect, it, vi } from "vitest";

import { GitHubError } from "../../github/api.ts";
import type { GitHubClient } from "../../github/client.ts";
import { AppNotInstalledError } from "../../github/errors.ts";
import { fetchInstallValidation } from "../handler.ts";

const ALL_PERMISSIONS = {
  administration: "write",
  metadata: "read",
  members: "write",
  organization_custom_roles: "read",
} as const;

type InstallChecks = Pick<GitHubClient, "fetchInstallation" | "verifyAppJwt">;

const newGitHub = (overrides: Partial<InstallChecks>): InstallChecks => ({
  verifyAppJwt: vi.fn(async () => true),
  fetchInstallation: vi.fn(async () => ({
    id: 42,
    permissions: ALL_PERMISSIONS,
    repositorySelection: "selected" as const,
    suspended: false,
    orgId: 9919,
  })),
  ...overrides,
});

const status = (code: number) =>
  new GitHubError({
    method: "GET",
    path: "/orgs/acme/installation",
    status: code,
    githubMessages: ["Not Found"],
  });

describe("fetchInstallValidation", () => {
  it("passes an installation with all four permissions, and reports the selection", async () => {
    await expect(fetchInstallValidation(newGitHub({}))).resolves.toEqual({
      keyAccepted: true,
      installed: true,
      suspended: false,
      missingPermissions: [],
      repositorySelection: "selected",
    });
  });

  it("reports a suspended installation", async () => {
    const github = newGitHub({
      fetchInstallation: vi.fn(async () => ({
        id: 42,
        permissions: ALL_PERMISSIONS,
        repositorySelection: "all" as const,
        suspended: true,
        orgId: 9919,
      })),
    });

    await expect(fetchInstallValidation(github)).resolves.toEqual({
      keyAccepted: true,
      installed: true,
      suspended: true,
      missingPermissions: [],
      repositorySelection: "all",
    });
  });

  it("reports a key GitHub doesn't accept", async () => {
    const github = newGitHub({ verifyAppJwt: vi.fn(async () => false) });

    await expect(fetchInstallValidation(github)).resolves.toEqual({
      keyAccepted: false,
      installed: false,
      suspended: false,
      missingPermissions: [],
      repositorySelection: null,
    });
    expect(github.fetchInstallation).not.toHaveBeenCalled();
  });

  it("reports an app that isn't installed on the org", async () => {
    const github = newGitHub({
      fetchInstallation: vi.fn(async () => {
        throw new AppNotInstalledError();
      }),
    });

    await expect(fetchInstallValidation(github)).resolves.toEqual({
      keyAccepted: true,
      installed: false,
      suspended: false,
      missingPermissions: [],
      repositorySelection: null,
    });
  });

  it("names each permission the installation lacks", async () => {
    const github = newGitHub({
      fetchInstallation: vi.fn(async () => ({
        id: 42,
        permissions: { metadata: "read" as const, members: "read" as const },
        repositorySelection: "all" as const,
        suspended: false,
        orgId: 9919,
      })),
    });

    await expect(fetchInstallValidation(github)).resolves.toEqual({
      keyAccepted: true,
      installed: true,
      suspended: false,
      // `members: read` is enough for the `role` access, but not the `team`
      // access.
      missingPermissions: [
        "administration=write",
        "members=write",
        "organization_custom_roles=read",
      ],
      repositorySelection: "all",
    });
  });

  it("names a permission with none granted at the `role` access's level too", async () => {
    const github = newGitHub({
      fetchInstallation: vi.fn(async () => ({
        id: 42,
        permissions: {
          administration: "write" as const,
          metadata: "read" as const,
          organization_custom_roles: "read" as const,
        },
        repositorySelection: "all" as const,
        suspended: false,
        orgId: 9919,
      })),
    });

    await expect(fetchInstallValidation(github)).resolves.toMatchObject({
      missingPermissions: ["members=read", "members=write"],
    });
  });

  it("fails on anything else", async () => {
    const github = newGitHub({
      fetchInstallation: vi.fn(async () => {
        throw status(502);
      }),
    });

    await expect(fetchInstallValidation(github)).rejects.toBeInstanceOf(
      GitHubError
    );
  });
});
