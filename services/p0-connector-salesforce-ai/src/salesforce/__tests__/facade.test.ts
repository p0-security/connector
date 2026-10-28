import { ConnectorError } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { newFacadeClient } from "../facade.ts";

const { mockedSleep } = vi.hoisted(() => ({
  mockedSleep: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("node:timers/promises", () => ({ setTimeout: mockedSleep }));

const mockedFetch = vi.fn();
vi.stubGlobal("fetch", mockedFetch);

const credentials = {
  domain: "acme.my.salesforce.com",
  consumerKey: "key-1",
  consumerSecret: "s3cret",
};

const USER_ID = "005000000000001AAA";

const jsonResponse = (data: unknown, status = 200) => ({
  ok: status < 300,
  status,
  statusText: "",
  json: async () => data,
});

const loggedIn = () =>
  mockedFetch.mockResolvedValueOnce(jsonResponse({ access_token: "tok" }));

beforeEach(() => {
  mockedFetch.mockReset();
  mockedSleep.mockClear();
});

describe("newFacadeClient", () => {
  it("logs in with the client credentials grant at the org's domain", async () => {
    loggedIn();

    await newFacadeClient(credentials);

    const [url, init] = mockedFetch.mock.calls[0];
    expect(url).toBe("https://acme.my.salesforce.com/services/oauth2/token");
    expect(Object.fromEntries(init.body)).toEqual({
      grant_type: "client_credentials",
      client_id: "key-1",
      client_secret: "s3cret",
    });
  });

  it("does not put the consumer secret in a failed login's error", async () => {
    mockedFetch.mockResolvedValueOnce(
      jsonResponse({ error: "invalid_client" }, 400)
    );

    const error = await newFacadeClient(credentials).catch((e) => e);

    expect(error).toBeInstanceOf(ConnectorError);
    expect(error.message).toContain("invalid_client");
    expect(JSON.stringify(error)).not.toContain("s3cret");
  });

  it("reports a refused login as a broken installation", async () => {
    mockedFetch.mockResolvedValueOnce(
      jsonResponse(
        {
          error: "invalid_client_id",
          error_description: "client identifier invalid",
        },
        400
      )
    );

    const error = await newFacadeClient(credentials).catch((e) => e);

    expect(error.data).toMatchObject({
      type: "insufficient_privileges",
      payload: { status: 400 },
    });
    expect(error.message).toContain("client identifier invalid");
    expect(error.message).toContain("provisioner consumer key");
  });

  it("does not try a refused login again", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse({ error: "invalid_client" }, 400)
    );

    await newFacadeClient(credentials).catch((e) => e);

    expect(mockedFetch).toHaveBeenCalledTimes(1);
  });

  it("tries again after a 404 with no error body", async () => {
    mockedFetch.mockResolvedValueOnce(jsonResponse({}, 404));
    loggedIn();

    await newFacadeClient(credentials);

    expect(mockedFetch).toHaveBeenCalledTimes(2);
    expect(mockedSleep).toHaveBeenCalledWith(1_000);
  });

  it("tries again after a network failure", async () => {
    mockedFetch.mockRejectedValueOnce(new TypeError("fetch failed"));
    loggedIn();

    await newFacadeClient(credentials);

    expect(mockedFetch).toHaveBeenCalledTimes(2);
  });

  it("does not try a 404 with a Salesforce error again", async () => {
    mockedFetch.mockResolvedValue(
      jsonResponse(
        { error: "not_found", error_description: "no such app" },
        404
      )
    );

    const error = await newFacadeClient(credentials).catch((e) => e);

    expect(mockedFetch).toHaveBeenCalledTimes(1);
    expect(error.data.type).toBe("object_not_found");
  });

  it("reports an unavailable Salesforce login as unavailable after four tries", async () => {
    mockedFetch.mockResolvedValue(jsonResponse({}, 503));

    const error = await newFacadeClient(credentials).catch((e) => e);

    expect(error.data.type).toBe("upstream_unavailable");
    expect(mockedFetch).toHaveBeenCalledTimes(4);
    expect(mockedSleep.mock.calls.map(([ms]) => ms)).toEqual([
      1_000, 2_000, 4_000,
    ]);
  });
});

describe("facade calls", () => {
  it("finds an agent by key", async () => {
    loggedIn();
    const facade = await newFacadeClient(credentials);
    mockedFetch.mockResolvedValueOnce(
      jsonResponse({ userId: USER_ID, username: "u", active: false })
    );

    await expect(facade.findAgent("abc123")).resolves.toEqual({
      userId: USER_ID,
      username: "u",
      active: false,
    });
    const [url, init] = mockedFetch.mock.calls[1];
    expect(url).toBe(
      "https://acme.my.salesforce.com/services/apexrest/p0/agents?agentKey=abc123"
    );
    expect(init.headers.Authorization).toBe("Bearer tok");
  });

  it("answers null for an agent that does not exist", async () => {
    loggedIn();
    const facade = await newFacadeClient(credentials);
    mockedFetch.mockResolvedValueOnce(
      jsonResponse({ error: "agent_not_found" }, 404)
    );

    await expect(facade.findAgent("abc123")).resolves.toBeNull();
  });

  it("sets the full grant set with PUT", async () => {
    loggedIn();
    const facade = await newFacadeClient(credentials);
    mockedFetch.mockResolvedValueOnce(jsonResponse({ permissionSets: ["A"] }));

    await facade.setGrants(USER_ID, ["A"]);

    const [url, init] = mockedFetch.mock.calls[1];
    expect(url).toBe(
      `https://acme.my.salesforce.com/services/apexrest/p0/agents/${USER_ID}/grants`
    );
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body)).toEqual({ permissionSets: ["A"] });
  });

  it("fails with the facade's error for a refused grant", async () => {
    loggedIn();
    const facade = await newFacadeClient(credentials);
    mockedFetch.mockResolvedValueOnce(
      jsonResponse({ error: "permission_set_not_grantable" }, 403)
    );

    await expect(facade.setGrants(USER_ID, ["B"])).rejects.toThrow(
      "permission_set_not_grantable"
    );
  });
});
