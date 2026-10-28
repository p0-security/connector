import { ConnectorError } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  createServiceAccessToken,
  findServiceAccessTokenId,
  listUserPermissions,
  revokeServiceAccessToken,
  updateServiceAccessTokenScopes,
} from "../datadog-api.ts";

const mockedFetch = vi.fn();
vi.stubGlobal("fetch", mockedFetch);

const auth = {
  site: "datadoghq.com",
  apiKey: "admin-api",
  appKey: "admin-app",
};

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

describe("createServiceAccessToken", () => {
  it("POSTs the scopes to the service account and maps the response", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse(
        { data: { id: "tok-1", attributes: { key: "secret-token" } } },
        { status: 201 }
      )
    );

    await expect(
      createServiceAccessToken(auth, {
        serviceAccountId: "sa-1",
        name: "P0 grant r-1",
        scopes: ["logs_read_data"],
      })
    ).resolves.toEqual({ id: "tok-1", key: "secret-token" });

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe(
      "https://api.datadoghq.com/api/v2/service_accounts/sa-1/access_tokens"
    );
    expect(init).toEqual(
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "DD-API-KEY": "admin-api",
          "DD-APPLICATION-KEY": "admin-app",
        }),
      })
    );
    expect(JSON.parse(init.body)).toEqual({
      data: {
        type: "service_access_tokens",
        attributes: { name: "P0 grant r-1", scopes: ["logs_read_data"] },
      },
    });
  });
});

describe("sites", () => {
  it("calls the API host of the organization's site", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ data: [] }));

    await listUserPermissions({ ...auth, site: "us5.datadoghq.com" }, "sa-1");

    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.us5.datadoghq.com/api/v2/users/sa-1/permissions",
      expect.anything()
    );
  });
});

describe("findServiceAccessTokenId", () => {
  const find = () =>
    findServiceAccessTokenId(auth, { serviceAccountId: "sa-1", name: "P0 x" });
  const tokens = (...names: string[]) =>
    jsonResponse({
      data: names.map((name, i) => ({ id: `tok-${i}`, attributes: { name } })),
    });

  it("filters by name and returns the exact match", async () => {
    mockedFetch.mockResolvedValue(tokens("P0 x-other", "P0 x"));

    await expect(find()).resolves.toBe("tok-1");
    const [url] = mockedFetch.mock.calls[0];
    expect(url).toContain("/api/v2/service_accounts/sa-1/access_tokens?");
    expect(new URL(url).searchParams.get("filter")).toBe("P0 x");
  });

  it("returns undefined when no token has the name", async () => {
    mockedFetch.mockResolvedValue(tokens("P0 x-other"));

    await expect(find()).resolves.toBeUndefined();
  });

  it("reads every page", async () => {
    mockedFetch
      .mockResolvedValueOnce(tokens(...Array(100).fill("P0 other")))
      .mockResolvedValueOnce(tokens("P0 x"));

    await expect(find()).resolves.toBe("tok-0");
    expect(mockedFetch).toHaveBeenCalledTimes(2);
  });

  it("fails when two tokens have the name", async () => {
    mockedFetch.mockResolvedValue(tokens("P0 x", "P0 x"));

    await expect(find()).rejects.toThrow(/More than one/);
  });
});

describe("updateServiceAccessTokenScopes", () => {
  it("PATCHes the token's scopes", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({ data: { id: "tok-1" } }));

    await updateServiceAccessTokenScopes(auth, {
      serviceAccountId: "sa-1",
      tokenId: "tok-1",
      scopes: ["logs_read_data", "metrics_read"],
    });

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe(
      "https://api.datadoghq.com/api/v2/service_accounts/sa-1/access_tokens/tok-1"
    );
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body)).toEqual({
      data: {
        id: "tok-1",
        type: "service_access_tokens",
        attributes: { scopes: ["logs_read_data", "metrics_read"] },
      },
    });
  });
});

describe("revokeServiceAccessToken", () => {
  const revoke = () =>
    revokeServiceAccessToken(auth, {
      serviceAccountId: "sa-1",
      tokenId: "tok-1",
    });

  it("accepts a 204 response", async () => {
    mockedFetch.mockResolvedValue(jsonResponse(undefined, { status: 204 }));

    await expect(revoke()).resolves.toBeUndefined();
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.datadoghq.com/api/v2/service_accounts/sa-1/access_tokens/tok-1",
      expect.objectContaining({ method: "DELETE" })
    );
  });

  it("treats a token that is already gone as revoked", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({ errors: ["Not found"] }, { ok: false, status: 404 })
    );

    await expect(revoke()).resolves.toBeUndefined();
  });

  it("reports Datadog's JSON:API error detail", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse(
        {
          errors: [
            {
              title: "Generic Error",
              detail: "service account access token not found",
            },
          ],
        },
        { ok: false, status: 400, statusText: "Bad Request" }
      )
    );

    await expect(revoke()).rejects.toThrow(
      "(400): service account access token not found"
    );
  });

  it("propagates any other failure", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({ errors: ["Forbidden"] }, { ok: false, status: 403 })
    );

    const error = await revoke().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data).toEqual(
      expect.objectContaining({
        type: "insufficient_privileges",
        message: expect.stringContaining("Forbidden"),
      })
    );
  });
});

describe("listUserPermissions", () => {
  it("returns the permission names", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({
        data: [
          {
            attributes: {
              name: "logs_read_data",
              display_name: "Logs Read Data",
            },
          },
        ],
      })
    );

    await expect(listUserPermissions(auth, "sa-1")).resolves.toEqual([
      { name: "logs_read_data", displayName: "Logs Read Data" },
    ]);
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://api.datadoghq.com/api/v2/users/sa-1/permissions",
      expect.objectContaining({ method: "GET" })
    );
  });
});

describe("request failures", () => {
  it("does not put the keys in the error", async () => {
    mockedFetch.mockRejectedValue(new Error("socket hang up"));

    const error = await createServiceAccessToken(auth, {
      serviceAccountId: "sa-1",
      name: "x",
      scopes: [],
    }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConnectorError);
    expect(JSON.stringify((error as ConnectorError).data)).not.toMatch(
      /admin-api|admin-app/
    );
  });
});
