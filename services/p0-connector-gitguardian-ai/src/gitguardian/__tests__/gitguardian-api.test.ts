import { ConnectorError } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getCurrentToken } from "../gitguardian-api.ts";

const mockedFetch = vi.fn();
vi.stubGlobal("fetch", mockedFetch);

const TOKEN = "admin-token-value";

const jsonResponse = (data: unknown, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  statusText: "",
  json: async () => data,
});

const self = {
  id: "tok-1",
  name: "P0 connector admin",
  type: "personal_access_token",
  scopes: ["api_tokens:write"],
  member_id: 1,
  workspace_id: 942194,
  expire_at: null,
  status: "active",
};

beforeEach(() => {
  mockedFetch.mockReset();
});

describe("getCurrentToken", () => {
  it.each([
    ["us", "https://api.gitguardian.com/v1/api_tokens/self"],
    ["eu", "https://api.eu1.gitguardian.com/v1/api_tokens/self"],
  ] as const)("calls the %s host with a Token header", async (region, url) => {
    mockedFetch.mockResolvedValue(jsonResponse(self));

    await expect(getCurrentToken({ region, token: TOKEN })).resolves.toEqual(
      self
    );

    const [calledUrl, init] = mockedFetch.mock.calls[0];
    expect(calledUrl).toBe(url);
    expect(init).toEqual(
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({ Authorization: `Token ${TOKEN}` }),
      })
    );
  });

  it("keeps the status and GitGuardian's detail on a non-2xx", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({ detail: "This token has already been revoked" }, 403)
    );

    const error = await getCurrentToken({ region: "us", token: TOKEN }).catch(
      (e: unknown) => e
    );

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data).toEqual(
      expect.objectContaining({
        type: "insufficient_privileges",
        payload: { status: 403, detail: "This token has already been revoked" },
      })
    );
  });

  it("reports a network failure as upstream_unavailable", async () => {
    mockedFetch.mockRejectedValue(new Error("socket hang up"));

    await expect(
      getCurrentToken({ region: "us", token: TOKEN })
    ).rejects.toMatchObject({ data: { type: "upstream_unavailable" } });
  });

  it("never puts the token in an error message", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({ detail: "Invalid API key." }, 401)
    );

    const error = (await getCurrentToken({ region: "us", token: TOKEN }).catch(
      (e: unknown) => e
    )) as ConnectorError;

    expect(error.message).not.toContain(TOKEN);
    expect(JSON.stringify(error.data)).not.toContain(TOKEN);
  });
});
