import { ConnectorError } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { listSupportedScopes, requestAppToken } from "../pagerduty-api.ts";

const mockedFetch = vi.fn();
vi.stubGlobal("fetch", mockedFetch);

const credentials = { clientId: "client-1", clientSecret: "s3cret" };

const jsonResponse = (
  data: unknown,
  init?: { ok?: boolean; status?: number; statusText?: string }
) => ({
  ok: init?.ok ?? true,
  status: init?.status ?? 200,
  statusText: init?.statusText ?? "OK",
  json: async () => data,
});

const tokenResponse = (scope: string) =>
  jsonResponse({
    access_token: "pdus+_token",
    scope,
    token_type: "bearer",
    expires_in: 86400,
  });

beforeEach(() => {
  mockedFetch.mockReset();
});

describe("requestAppToken", () => {
  it("POSTs a client credentials grant for the account's scopes and users.read", async () => {
    mockedFetch.mockResolvedValue(
      tokenResponse(
        "as_account-eu.acme incidents.read services.read users.read"
      )
    );

    await expect(
      requestAppToken(credentials, {
        region: "eu",
        subdomain: "acme",
        scopes: ["incidents.read", "services.read"],
      })
    ).resolves.toBe("pdus+_token");

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe("https://identity.pagerduty.com/oauth/token");
    expect(init).toEqual(
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "application/x-www-form-urlencoded",
        }),
      })
    );
    expect(Object.fromEntries(init.body)).toEqual({
      grant_type: "client_credentials",
      client_id: "client-1",
      client_secret: "s3cret",
      scope: "as_account-eu.acme incidents.read services.read users.read",
    });
  });

  it("requests users.read once when the grant asks for it", async () => {
    mockedFetch.mockResolvedValue(
      tokenResponse("as_account-us.acme users.read")
    );

    await requestAppToken(credentials, {
      region: "us",
      subdomain: "acme",
      scopes: ["users.read"],
    });

    expect(Object.fromEntries(mockedFetch.mock.calls[0][1].body).scope).toBe(
      "as_account-us.acme users.read"
    );
  });

  it("fails when PagerDuty leaves out a scope that the app does not hold", async () => {
    mockedFetch.mockResolvedValue(
      tokenResponse("as_account-us.acme incidents.read")
    );

    const error = await requestAppToken(credentials, {
      region: "us",
      subdomain: "acme",
      scopes: ["incidents.read", "incidents.write"],
    }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data.type).toBe("validation_error");
    expect((error as ConnectorError).message).toBe(
      "PagerDuty did not grant incidents.write, users.read. Make sure that the PagerDuty app holds these scopes."
    );
  });

  it("surfaces PagerDuty's error without the client secret", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse(
        { error: "invalid_client", error_description: "Bad client" },
        { ok: false, status: 401, statusText: "Unauthorized" }
      )
    );

    const error = await requestAppToken(credentials, {
      region: "us",
      subdomain: "acme",
      scopes: ["incidents.read"],
    }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).message).toBe(
      "PagerDuty token request failed (401): Bad client"
    );
    expect(JSON.stringify(error)).not.toContain("s3cret");
  });

  it("reports an unreachable PagerDuty as upstream_unavailable", async () => {
    mockedFetch.mockRejectedValue(new Error("ECONNRESET"));

    const error = await requestAppToken(credentials, {
      region: "us",
      subdomain: "acme",
      scopes: ["incidents.read"],
    }).catch((e: unknown) => e);

    expect((error as ConnectorError).data.type).toBe("upstream_unavailable");
  });
});

describe("listSupportedScopes", () => {
  it.each([
    ["us", "https://mcp.pagerduty.com"],
    ["eu", "https://mcp.eu.pagerduty.com"],
  ] as const)("reads the %s MCP server's metadata", async (region, origin) => {
    mockedFetch.mockResolvedValue(jsonResponse({ scopes_supported: [] }));

    await listSupportedScopes(region);

    expect(mockedFetch.mock.calls[0][0]).toBe(
      `${origin}/.well-known/oauth-protected-resource/mcp`
    );
  });

  it("drops the scopes that name no resource", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({
        scopes_supported: [
          "incidents.read",
          "none",
          "openid",
          "read",
          "write",
          "users:contact_methods.read",
        ],
      })
    );

    await expect(listSupportedScopes("us")).resolves.toEqual([
      "incidents.read",
      "users:contact_methods.read",
    ]);
  });
});
