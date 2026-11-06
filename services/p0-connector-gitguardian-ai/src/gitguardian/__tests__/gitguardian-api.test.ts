import { ConnectorError } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  getCurrentToken,
  listActiveTokens,
  mintToken,
} from "../gitguardian-api.ts";

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

describe("mintToken", () => {
  it("POSTs the name, type, scopes and lifetime", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ ...self, key: "k" }, 201));

    await mintToken(
      { region: "us", token: TOKEN },
      {
        name: "P0 abc 1",
        type: "personal_access_token",
        scopes: ["scan"],
        lifetime: 3,
      }
    );

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe("https://api.gitguardian.com/v1/api_tokens");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({
      name: "P0 abc 1",
      type: "personal_access_token",
      scopes: ["scan"],
      lifetime: 3,
    });
  });
});

describe("listActiveTokens", () => {
  const page = (data: unknown, link?: string) => ({
    ...jsonResponse(data),
    headers: new Headers(link ? { link } : {}),
  });

  it("follows the next page on the same host", async () => {
    mockedFetch
      .mockResolvedValueOnce(
        page(
          [self],
          '<https://api.gitguardian.com/v1/api_tokens?cursor=abc>; rel="next"'
        )
      )
      .mockResolvedValueOnce(page([{ ...self, id: "tok-2" }]));

    const tokens = await listActiveTokens({ region: "us", token: TOKEN }, 1);

    expect(tokens.map(({ id }) => id)).toEqual(["tok-1", "tok-2"]);
    expect(mockedFetch.mock.calls.map(([url]) => url)).toEqual([
      "https://api.gitguardian.com/v1/api_tokens?member_id=1&status=active&per_page=100",
      "https://api.gitguardian.com/v1/api_tokens?cursor=abc",
    ]);
  });

  it("refuses a next page on another host", async () => {
    mockedFetch.mockResolvedValueOnce(
      page(
        [self],
        '<https://evil.example/v1/api_tokens?cursor=abc>; rel="next"'
      )
    );

    await expect(
      listActiveTokens({ region: "us", token: TOKEN }, 1)
    ).rejects.toThrow(/another host: evil.example/);
    expect(mockedFetch).toHaveBeenCalledTimes(1);
  });
});
