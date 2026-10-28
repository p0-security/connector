import { ConnectorError } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { newAtlasClient, requestToken } from "../atlas-api.ts";

const mockedFetch = vi.fn();
vi.stubGlobal("fetch", mockedFetch);

const PROJECT = "0123456789abcdef01234567";
const PROJECT_URL = `https://cloud.mongodb.com/api/atlas/v2/groups/${PROJECT}`;

const jsonResponse = (data: unknown, init?: { status?: number }) => {
  const status = init?.status ?? 200;
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    json: async () => data,
    text: async () => (data === undefined ? "" : JSON.stringify(data)),
  };
};

const config = (name: string) => ({
  mcpConfigId: `id-${name}`,
  mcpConfigName: name,
  clientId: `mdb_sa_id_${name}`,
  roles: ["GROUP_READ_ONLY"],
});

beforeEach(() => {
  mockedFetch.mockReset();
});

describe("requestToken", () => {
  it("POSTs a client credentials grant with basic auth", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({ access_token: "tok", expires_in: 3600 })
    );

    await expect(
      requestToken({ clientId: "mdb_sa_id_1", clientSecret: "s3cret" })
    ).resolves.toBe("tok");

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe("https://cloud.mongodb.com/api/oauth/token");
    expect(init.headers.Authorization).toBe(
      `Basic ${Buffer.from("mdb_sa_id_1:s3cret").toString("base64")}`
    );
    expect(Object.fromEntries(init.body)).toEqual({
      grant_type: "client_credentials",
    });
  });

  it("surfaces Atlas's message, not the credentials", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse(
        {
          error: "invalid_client",
          error_description: "The provided credentials are not valid",
        },
        { status: 401 }
      )
    );

    const error = await requestToken({
      clientId: "mdb_sa_id_1",
      clientSecret: "s3cret",
    }).catch((e) => e);
    expect(error).toBeInstanceOf(ConnectorError);
    expect(error.message).toBe(
      "Atlas token request failed (401): The provided credentials are not valid"
    );
    expect(JSON.stringify(error)).not.toContain("s3cret");
  });

  it("converts a network failure", async () => {
    mockedFetch.mockRejectedValue(new Error("ECONNRESET"));

    await expect(
      requestToken({ clientId: "mdb_sa_id_1", clientSecret: "s3cret" })
    ).rejects.toThrow("Atlas token request failed: ECONNRESET");
  });
});

describe("newAtlasClient", () => {
  const atlas = newAtlasClient("admin-token", PROJECT);

  it("finds a configuration by name across pages", async () => {
    const firstPage = Array.from({ length: 500 }, (_, i) => config(`c${i}`));
    mockedFetch
      .mockResolvedValueOnce(jsonResponse({ results: firstPage }))
      .mockResolvedValueOnce(jsonResponse({ results: [config("p0-x")] }));

    await expect(atlas.findMcpConfig("p0-x")).resolves.toEqual(config("p0-x"));
    expect(mockedFetch.mock.calls.map(([url]) => url)).toEqual([
      `${PROJECT_URL}/mcpConfigs?itemsPerPage=500&pageNum=1`,
      `${PROJECT_URL}/mcpConfigs?itemsPerPage=500&pageNum=2`,
    ]);
    expect(mockedFetch.mock.calls[0][1].headers).toEqual({
      Accept: "application/vnd.atlas.2025-03-12+json",
      Authorization: "Bearer admin-token",
    });
  });

  it("finds no configuration that is not there", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ results: [config("a")] }));

    await expect(atlas.findMcpConfig("p0-x")).resolves.toBeUndefined();
  });

  it("creates a configuration with its roles", async () => {
    mockedFetch.mockResolvedValue(jsonResponse(config("p0-x")));

    await atlas.createMcpConfig("p0-x", ["GROUP_DATA_ACCESS_READ_ONLY"]);

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe(`${PROJECT_URL}/mcpConfigs`);
    expect(init.method).toBe("POST");
    expect(init.headers["Content-Type"]).toBe(
      "application/vnd.atlas.2025-03-12+json"
    );
    expect(JSON.parse(init.body)).toEqual({
      mcpConfigName: "p0-x",
      roles: ["GROUP_DATA_ACCESS_READ_ONLY"],
    });
  });

  it("deletes a configuration with its secrets", async () => {
    mockedFetch.mockResolvedValue(jsonResponse(undefined, { status: 204 }));

    await atlas.deleteMcpConfig("id-1");

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe(`${PROJECT_URL}/mcpConfigs/id-1?cascading=true`);
    expect(init.method).toBe("DELETE");
  });

  it("ignores a configuration that is already gone", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({}, { status: 404 }));

    await expect(atlas.deleteMcpConfig("id-1")).resolves.toBeUndefined();
  });

  it("creates a secret with the shortest default lifetime", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({ id: "s1", createdAt: "t", secret: "mdb_sa_sk_x" })
    );

    await expect(atlas.createMcpConfigSecret("id-1")).resolves.toEqual({
      id: "s1",
      createdAt: "t",
      secret: "mdb_sa_sk_x",
    });
    expect(JSON.parse(mockedFetch.mock.calls[0][1].body)).toEqual({
      secretExpiresAfterHours: 8,
    });
  });

  it("surfaces a refused secret", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse(
        {
          detail:
            "Service Account secret limit (2) reached. Service account (mdb_sa_id_1) has 2 secrets.",
        },
        { status: 400 }
      )
    );

    await expect(atlas.createMcpConfigSecret("id-1")).rejects.toThrow(
      "Atlas MCP configuration secret create failed (400): Service Account secret limit (2) reached."
    );
  });
});
