import { ConnectorError } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AccessTokenRequest } from "../context.ts";
import { githubClientFor } from "../github-client.ts";

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factories run.
const {
  createAppJwt,
  getSoleInstallationId,
  createAccessToken,
  listRepositories,
} = vi.hoisted(() => ({
  createAppJwt: vi.fn(),
  getSoleInstallationId: vi.fn(),
  createAccessToken: vi.fn(),
  listRepositories: vi.fn(),
}));

vi.mock("../jwt.ts", () => ({ createAppJwt }));
vi.mock("../installations.ts", () => ({ getSoleInstallationId }));
vi.mock("../github-api.ts", () => ({ createAccessToken, listRepositories }));

const clientContext = {
  privateKey: "PEM-KEY",
  appId: 12345,
};

const accessRequest: AccessTokenRequest = {
  repository: "repo-a",
  permissions: { contents: "read" },
};

describe("githubClientFor", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    createAppJwt.mockReturnValue("signed-jwt");
    getSoleInstallationId.mockResolvedValue(67890);
    createAccessToken.mockResolvedValue({
      token: "ghs_final",
      expiresAt: "2026-07-14T12:00:00Z",
    });
  });

  describe("mintInstallationAccessToken", () => {
    /** Builds the client and mints in one step, matching how callers use the factory. */
    const mint = async (overrides: Partial<typeof accessRequest> = {}) =>
      (await githubClientFor(clientContext)).mintInstallationAccessToken({
        ...accessRequest,
        ...overrides,
      });

    it("returns the scoped installation token", async () => {
      await expect(mint()).resolves.toBe("ghs_final");
    });

    const githubError = (status: number, githubMessage: string) =>
      new ConnectorError({
        type: "unknown",
        message: `GitHub post /app/installations/67890/access_tokens failed (${status}): ${githubMessage}`,
        payload: { status, githubMessage },
      });

    it("names the repository and permissions when GitHub refuses the scope", async () => {
      createAccessToken.mockRejectedValue(
        githubError(
          422,
          "The permissions requested are not granted to this installation."
        )
      );

      const error = await mint({
        permissions: { contents: "write", metadata: "read" },
      }).catch((e: unknown) => e);

      expect(error).toBeInstanceOf(ConnectorError);
      expect((error as ConnectorError).data).toMatchObject({
        type: "validation_error",
        message:
          "GitHub did not give a token for repo-a with contents:write, metadata:read (The permissions requested are not granted to this installation). Make sure that the GitHub App has these permissions, that the organization approved them, and that the App can access repo-a.",
        payload: {
          status: 422,
          repository: "repo-a",
          permissions: "contents:write, metadata:read",
        },
      });
    });

    it("keeps other GitHub errors unchanged", async () => {
      const error = githubError(500, "Server Error");
      createAccessToken.mockRejectedValue(error);

      await expect(mint()).rejects.toBe(error);
    });
  });

  describe("listAllRepositories", () => {
    const repo = (id: number) => ({
      id,
      name: `repo-${id}`,
      full_name: `org/repo-${id}`,
      description: "",
    });

    it("walks every page and returns the full repository list", async () => {
      listRepositories
        .mockResolvedValueOnce({ total: 3, repositories: [repo(1), repo(2)] })
        .mockResolvedValueOnce({ total: 3, repositories: [repo(3)] });

      const repositories = await (
        await githubClientFor(clientContext)
      ).listAllRepositories();

      expect(repositories).toEqual([repo(1), repo(2), repo(3)]);
      expect(listRepositories).toHaveBeenNthCalledWith(1, {
        auth: { token: "ghs_final" },
        page: 1,
        per_page: 100,
      });
      expect(listRepositories).toHaveBeenNthCalledWith(2, {
        auth: { token: "ghs_final" },
        page: 2,
        per_page: 100,
      });
    });
  });
});
