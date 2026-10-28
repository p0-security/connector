import { describe, expect, it, vi } from "vitest";

import { GitHubError } from "../../github/api.ts";
import type { GitHubClient } from "../../github/client.ts";
import { AppNotInstalledError } from "../../github/errors.ts";
import { getInstallValidation } from "../handler.ts";

const ALL_PERMISSIONS = {
  administration: "write",
  metadata: "read",
  members: "read",
  organization_custom_roles: "read",
} as const;

type InstallChecks = Pick<
  GitHubClient,
  "findInstallation" | "isAppJwtAccepted"
>;

const newGitHub = (overrides: Partial<InstallChecks>): InstallChecks => ({
  isAppJwtAccepted: vi.fn(async () => true),
  findInstallation: vi.fn(async () => ({
    id: 42,
    permissions: ALL_PERMISSIONS,
    repositorySelection: "selected" as const,
    suspended: false,
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

describe("getInstallValidation", () => {
  it("passes an installation with all four permissions, and reports the selection", async () => {
    await expect(getInstallValidation(newGitHub({}))).resolves.toEqual({
      keyAccepted: true,
      installed: true,
      suspended: false,
      missingPermissions: [],
      repositorySelection: "selected",
    });
  });

  it("reports a suspended installation", async () => {
    const github = newGitHub({
      findInstallation: vi.fn(async () => ({
        id: 42,
        permissions: ALL_PERMISSIONS,
        repositorySelection: "all" as const,
        suspended: true,
      })),
    });

    await expect(getInstallValidation(github)).resolves.toEqual({
      keyAccepted: true,
      installed: true,
      suspended: true,
      missingPermissions: [],
      repositorySelection: "all",
    });
  });

  it("reports a key GitHub doesn't accept", async () => {
    const github = newGitHub({ isAppJwtAccepted: vi.fn(async () => false) });

    await expect(getInstallValidation(github)).resolves.toEqual({
      keyAccepted: false,
      installed: false,
      suspended: false,
      missingPermissions: [],
      repositorySelection: null,
    });
    expect(github.findInstallation).not.toHaveBeenCalled();
  });

  it("reports an app that isn't installed on the org", async () => {
    const github = newGitHub({
      findInstallation: vi.fn(async () => {
        throw new AppNotInstalledError();
      }),
    });

    await expect(getInstallValidation(github)).resolves.toEqual({
      keyAccepted: true,
      installed: false,
      suspended: false,
      missingPermissions: [],
      repositorySelection: null,
    });
  });

  it("names each permission the installation lacks", async () => {
    const github = newGitHub({
      findInstallation: vi.fn(async () => ({
        id: 42,
        permissions: { metadata: "read" as const, members: "read" as const },
        repositorySelection: "all" as const,
        suspended: false,
      })),
    });

    await expect(getInstallValidation(github)).resolves.toEqual({
      keyAccepted: true,
      installed: true,
      suspended: false,
      missingPermissions: [
        "administration=write",
        "organization_custom_roles=read",
      ],
      repositorySelection: "all",
    });
  });

  it("fails on anything else", async () => {
    const github = newGitHub({
      findInstallation: vi.fn(async () => {
        throw status(502);
      }),
    });

    await expect(getInstallValidation(github)).rejects.toBeInstanceOf(
      GitHubError
    );
  });
});
