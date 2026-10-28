import { ConnectorError } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  createAccessToken,
  getAppInstallations,
  listRepositories,
} from "../github-api.ts";

// Stub the global `fetch` so no real network call is made.
const mockedFetch = vi.fn();
vi.stubGlobal("fetch", mockedFetch);

/** Builds a minimal `Response`-like object matching what `githubRequest` reads. */
const jsonResponse = (
  data: unknown,
  init?: { ok?: boolean; status?: number; statusText?: string }
) => ({
  ok: init?.ok ?? true,
  status: init?.status ?? 200,
  statusText: init?.statusText ?? "OK",
  json: async () => data,
});

beforeEach(() => {
  mockedFetch.mockReset();
});

describe("getAppInstallations", () => {
  it("returns the installations reported by the authenticated endpoint", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse([{ id: 42, account: { login: "acme" } }])
    );

    await expect(getAppInstallations({ token: "jwt-1" })).resolves.toEqual([
      { id: 42, accountLogin: "acme" },
    ]);
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/app/installations",
      expect.objectContaining({
        method: "get",
        headers: expect.objectContaining({ Authorization: "Bearer jwt-1" }),
      })
    );
  });
});

describe("createAccessToken", () => {
  it("POSTs to the installation endpoint with scope and maps the response", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({ token: "ghs_abc", expires_at: "2026-07-14T12:00:00Z" })
    );

    await expect(
      createAccessToken({
        auth: { token: "jwt-123" },
        installationId: 42,
        repositories: ["repo-a"],
        permissions: { contents: "read" },
      })
    ).resolves.toEqual({ token: "ghs_abc", expiresAt: "2026-07-14T12:00:00Z" });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/app/installations/42/access_tokens",
      expect.objectContaining({
        method: "post",
        body: JSON.stringify({
          repositories: ["repo-a"],
          permissions: { contents: "read" },
        }),
        headers: expect.objectContaining({ Authorization: "Bearer jwt-123" }),
      })
    );
  });
});

describe("listRepositories", () => {
  it("GETs the installation repositories endpoint and maps the response", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({
        total_count: 1,
        repositories: [
          {
            id: 1,
            name: "repo-a",
            full_name: "acme/repo-a",
            description: "",
          },
        ],
      })
    );

    await expect(
      listRepositories({
        auth: { token: "ghs_abc" },
        page: 1,
        per_page: 100,
      })
    ).resolves.toEqual({
      total: 1,
      repositories: [
        { id: 1, name: "repo-a", full_name: "acme/repo-a", description: "" },
      ],
    });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.github.com/installation/repositories?per_page=100&page=1",
      expect.objectContaining({
        method: "get",
        body: undefined,
        headers: expect.objectContaining({ Authorization: "Bearer ghs_abc" }),
      })
    );
  });
});

describe("error conversion", () => {
  it("converts a non-2xx response into a ConnectorError carrying GitHub's message but not the JWT", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse(
        { message: "Bad credentials" },
        { ok: false, status: 403, statusText: "Forbidden" }
      )
    );

    const error = await createAccessToken({
      auth: { token: "SECRET_JWT" },
      installationId: 1,
      repositories: ["repo-a"],
      permissions: { contents: "read" },
    }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).message).toContain("Bad credentials");
    expect((error as ConnectorError).message).not.toContain("SECRET_JWT");
    expect((error as ConnectorError).data.type).toBe("insufficient_privileges");
  });
});
