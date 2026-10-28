import { beforeEach, describe, expect, it, vi } from "vitest";

import { getSoleInstallationId } from "../installations.ts";

const { getAppInstallations } = vi.hoisted(() => ({
  getAppInstallations: vi.fn(),
}));

vi.mock("../github-api.ts", () => ({ getAppInstallations }));

beforeEach(() => {
  vi.clearAllMocks();
});

describe("getSoleInstallationId", () => {
  it("returns the id of the single installation", async () => {
    getAppInstallations.mockResolvedValue([{ id: 42, accountLogin: "acme" }]);

    await expect(getSoleInstallationId({ token: "jwt-1" })).resolves.toBe(42);
    expect(getAppInstallations).toHaveBeenCalledWith({ token: "jwt-1" });
  });

  it("throws when the App has no installations", async () => {
    getAppInstallations.mockResolvedValue([]);
    await expect(getSoleInstallationId({ token: "j" })).rejects.toThrow(
      "No GitHub App installation found"
    );
  });

  it("throws, naming the accounts, when there is more than one installation", async () => {
    getAppInstallations.mockResolvedValue([
      { id: 1, accountLogin: "org-a" },
      { id: 2, accountLogin: "org-b" },
    ]);
    await expect(getSoleInstallationId({ token: "j" })).rejects.toThrow(
      "found 2: org-a, org-b"
    );
  });
});
