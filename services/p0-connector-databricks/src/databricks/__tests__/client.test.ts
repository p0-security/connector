import { ConnectorError } from "@p0security/connector";
import { type Server, createServer } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ACCOUNTS_URL,
  ACCOUNT_ID,
  APPLICATION_ID,
  SP_SCIM_ID,
  WORKSPACE_URL,
  accountContext,
  fetchCalls,
  isTokenExchange,
  jsonResponse,
  resetBetweenTests,
  stubFetch,
} from "../../__tests__/http.ts";
import { AWS_JWT } from "../../__tests__/sts.ts";
import {
  assertNotOwnPrincipal,
  isWorkspaceAdmin,
  newDatabricksClient,
} from "../client.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);

resetBetweenTests();

const meResponse = {
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
  id: SP_SCIM_ID,
  userName: APPLICATION_ID,
  displayName: "p0-connector",
  active: true,
};

const servicePrincipals = (
  ...principals: { id: string; applicationId: string }[]
) => jsonResponse({ totalResults: principals.length, Resources: principals });

describe("newDatabricksClient", () => {
  describe("inWorkspace(url).ownIdentity", () => {
    it("reads the connector's identity from the workspace's SCIM /Me with the federated token", async () => {
      const fetchMock = stubFetch(() => jsonResponse(meResponse));
      const client = newDatabricksClient(accountContext());

      await expect(
        client.inWorkspace(WORKSPACE_URL).ownIdentity()
      ).resolves.toEqual({
        id: SP_SCIM_ID,
        userName: APPLICATION_ID,
        displayName: "p0-connector",
      });

      const me = fetchCalls(fetchMock).find((c) => !isTokenExchange(c));
      expect(me?.url).toBe(`${WORKSPACE_URL}/api/2.0/preview/scim/v2/Me`);
      expect(me?.init.method).toBe("GET");
      expect(me?.init.headers.Authorization).toBe("Bearer dbx-token-1");
    });

    it("reads the groups /Me lists", async () => {
      const groups = [
        { display: "users", value: "101", $ref: "Groups/101" },
        { display: "admins", value: "100", $ref: "Groups/100" },
      ];
      stubFetch(() => jsonResponse({ ...meResponse, groups }));

      await expect(
        newDatabricksClient(accountContext())
          .inWorkspace(WORKSPACE_URL)
          .ownIdentity()
      ).resolves.toMatchObject({
        groups: [
          { display: "users", value: "101" },
          { display: "admins", value: "100" },
        ],
      });
    });

    it("rejects a /Me response with no id", async () => {
      stubFetch(() => jsonResponse({ userName: APPLICATION_ID }));
      const client = newDatabricksClient(accountContext());

      await expect(
        client.inWorkspace(WORKSPACE_URL).ownIdentity()
      ).rejects.toMatchObject({
        data: { type: "unknown" },
      });
    });
  });

  describe("ownServicePrincipal", () => {
    it("finds the principal in account SCIM by the application ID it federated as", async () => {
      const fetchMock = stubFetch(() =>
        servicePrincipals({ id: SP_SCIM_ID, applicationId: APPLICATION_ID })
      );
      const client = newDatabricksClient(accountContext());

      await expect(client.ownServicePrincipal()).resolves.toEqual({
        id: SP_SCIM_ID,
        applicationId: APPLICATION_ID,
      });
      const lookup = fetchCalls(fetchMock).find((c) => !isTokenExchange(c));
      expect(lookup?.url).toBe(
        `${ACCOUNTS_URL}/api/2.0/accounts/${ACCOUNT_ID}/scim/v2/ServicePrincipals?${new URLSearchParams(
          { filter: `applicationId eq "${APPLICATION_ID}"` }
        ).toString()}`
      );
    });

    it("ignores a principal the filter shouldn't have returned", async () => {
      stubFetch(() =>
        servicePrincipals({
          id: "1",
          applicationId: "00000000-0000-4000-8000-000000000000",
        })
      );

      await expect(
        newDatabricksClient(accountContext()).ownServicePrincipal()
      ).rejects.toMatchObject({ data: { type: "object_not_found" } });
    });

    it("looks the principal up once per account and application ID", async () => {
      const fetchMock = stubFetch((url) =>
        servicePrincipals({
          id: SP_SCIM_ID,
          applicationId: new URL(url).searchParams
            .get("filter")!
            .slice('applicationId eq "'.length, -1),
        })
      );
      const other = "11111111-2222-4333-8444-555555555555";

      await newDatabricksClient(accountContext()).ownServicePrincipal();
      await newDatabricksClient(accountContext()).ownServicePrincipal();
      await newDatabricksClient(
        accountContext({ applicationId: other })
      ).ownServicePrincipal();

      expect(
        fetchCalls(fetchMock).filter((c) => !isTokenExchange(c))
      ).toHaveLength(2);
    });

    it("says the principal isn't an account admin when account SCIM answers 403", async () => {
      stubFetch(() =>
        jsonResponse(
          { error_code: "PERMISSION_DENIED", message: "not an admin" },
          { status: 403 }
        )
      );

      await expect(
        newDatabricksClient(accountContext()).ownServicePrincipal()
      ).rejects.toMatchObject({
        message: `Service principal ${APPLICATION_ID} is not an account admin in Databricks account ${ACCOUNT_ID}`,
        data: { type: "insufficient_privileges" },
      });
    });

    it("doesn't cache a failed lookup", async () => {
      let calls = 0;
      stubFetch(() =>
        ++calls === 1
          ? jsonResponse({}, { status: 503 })
          : servicePrincipals({ id: SP_SCIM_ID, applicationId: APPLICATION_ID })
      );

      await expect(
        newDatabricksClient(accountContext()).ownServicePrincipal()
      ).rejects.toBeInstanceOf(ConnectorError);
      await expect(
        newDatabricksClient(accountContext()).ownServicePrincipal()
      ).resolves.toMatchObject({ id: SP_SCIM_ID });
    });
  });

  describe("User-Agent", () => {
    it("is sent on account calls", async () => {
      const fetchMock = stubFetch();
      const client = newDatabricksClient(accountContext({ requestId: "r-1" }));

      await client.account({ method: "GET", path: "/scim/v2/Users" });

      const call = fetchCalls(fetchMock).find((c) => !isTokenExchange(c));
      expect(call?.url).toBe(
        `${ACCOUNTS_URL}/api/2.0/accounts/${ACCOUNT_ID}/scim/v2/Users`
      );
      expect(call?.init.headers["User-Agent"]).toBe(
        "p0-connector-databricks/1.0.0 request/r-1"
      );
    });

    it("is sent on workspace calls", async () => {
      const fetchMock = stubFetch();
      const client = newDatabricksClient(accountContext({ requestId: "r-2" }));

      await client.inWorkspace(WORKSPACE_URL).call({
        method: "PATCH",
        path: "/api/2.1/unity-catalog/permissions/catalog/main",
        body: { changes: [] },
      });

      const call = fetchCalls(fetchMock).find((c) => !isTokenExchange(c));
      expect(call?.init.headers["User-Agent"]).toBe(
        "p0-connector-databricks/1.0.0 request/r-2"
      );
      expect(call?.init.headers["Content-Type"]).toBe("application/json");
      expect(call?.init.body).toBe(JSON.stringify({ changes: [] }));
    });

    it("is sent on every call, the token exchange included", async () => {
      const fetchMock = stubFetch(() => jsonResponse(meResponse));
      const client = newDatabricksClient(accountContext({ requestId: "r-3" }));

      await client.inWorkspace(WORKSPACE_URL).ownIdentity();
      await client.account({ method: "GET", path: "/scim/v2/Users" });

      const calls = fetchCalls(fetchMock);
      expect(calls).toHaveLength(3);
      for (const { init } of calls) {
        expect(init.headers["User-Agent"]).toBe(
          "p0-connector-databricks/1.0.0 request/r-3"
        );
      }
    });
  });

  it("refuses to send its token to a workspace URL that isn't Databricks", async () => {
    const fetchMock = stubFetch();
    const client = newDatabricksClient(accountContext());

    await expect(
      client
        .inWorkspace("https://evil.example")
        .call({ method: "GET", path: "/x" })
    ).rejects.toMatchObject({ data: { type: "validation_error" } });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("surfaces a Databricks error with its message and status", async () => {
    stubFetch(() =>
      jsonResponse(
        { error_code: "PERMISSION_DENIED", message: "not an admin" },
        { status: 403, statusText: "Forbidden" }
      )
    );
    const client = newDatabricksClient(accountContext());

    const error = await client
      .account({ method: "GET", path: "/scim/v2/Users" })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data).toMatchObject({
      type: "insufficient_privileges",
      payload: { status: 403, errorCode: "PERMISSION_DENIED" },
    });
    expect((error as ConnectorError).data.message).toContain("not an admin");
    expect(JSON.stringify((error as ConnectorError).data)).not.toContain(
      "dbx-token"
    );
  });
});

describe("response bodies", () => {
  const unreadable = (status: number, statusText = "OK") => ({
    ok: status >= 200 && status < 300,
    status,
    statusText,
    text: async () => {
      throw Object.assign(new Error("aborted"), { name: "TimeoutError" });
    },
  });

  it("reports a 2xx whose body can't be read as Databricks being unavailable", async () => {
    stubFetch(() => unreadable(200));

    await expect(
      newDatabricksClient(accountContext()).account({
        method: "GET",
        path: "/scim/v2/Users",
      })
    ).rejects.toMatchObject({
      data: { type: "upstream_unavailable", payload: { status: 200 } },
    });
  });

  it("falls back to the status text for an error response whose body can't be read", async () => {
    stubFetch(() => unreadable(502, "Bad Gateway"));

    await expect(
      newDatabricksClient(accountContext()).account({
        method: "GET",
        path: "/scim/v2/Users",
      })
    ).rejects.toMatchObject({
      message:
        "Databricks GET /api/2.0/accounts/" +
        ACCOUNT_ID +
        "/scim/v2/Users failed (502): Bad Gateway",
    });
  });

  it("returns undefined for a 2xx that isn't JSON, which the caller's parse then refuses", async () => {
    stubFetch(() => ({
      ok: true,
      status: 200,
      statusText: "OK",
      text: async () => "<html>proxy</html>",
    }));

    await expect(
      newDatabricksClient(accountContext())
        .inWorkspace(WORKSPACE_URL)
        .ownIdentity()
    ).rejects.toMatchObject({
      message: "Databricks SCIM /Me returned an unexpected response",
      data: { type: "unknown" },
    });
  });
});

describe("isWorkspaceAdmin", () => {
  const identity = (groups?: { display?: string; value: string }[]) => ({
    id: SP_SCIM_ID,
    ...(groups ? { groups } : {}),
  });

  it.each([
    ["the admins group", [{ display: "admins", value: "100" }], true],
    [
      "admins among others",
      [
        { display: "users", value: "101" },
        { display: "admins", value: "100" },
      ],
      true,
    ],
    ["only other groups", [{ display: "users", value: "101" }], false],
    ["admins only as an ID", [{ value: "admins" }], false],
    [
      "a group whose name only starts with admins",
      [{ display: "admins-ro", value: "1" }],
      false,
    ],
    ["no groups", [], false],
    ["no groups field", undefined, false],
  ])("is %s → %s", (_, groups, expected) => {
    expect(isWorkspaceAdmin(identity(groups))).toBe(expected);
  });
});

describe("assertNotOwnPrincipal", () => {
  const own = { id: SP_SCIM_ID, applicationId: APPLICATION_ID };

  it("refuses the connector's own service principal, by account SCIM ID", () => {
    expect(() => assertNotOwnPrincipal(own, { id: SP_SCIM_ID }, "req")).toThrow(
      expect.objectContaining({
        message:
          "P0 cannot grant access to its own Databricks service principal",
        data: expect.objectContaining({ type: "validation_error" }),
      })
    );
  });

  it("allows any other principal", () => {
    expect(() =>
      assertNotOwnPrincipal(own, { id: "1001" }, "req")
    ).not.toThrow();
  });
});

describe("redirects", () => {
  /** The real `fetch`, so a redirect is handled exactly as Node handles it. */
  const realFetch = globalThis.fetch;

  type Reply = { status: number; location?: string; body?: unknown };

  /** One request a local server received. */
  type Received = { method?: string; path?: string; body: string };

  const servers: Server[] = [];

  afterEach(async () => {
    for (const server of servers.splice(0)) {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  });

  /**
   * Starts an HTTP server on a free local port. It answers each request with
   * `reply(path)` and records what it received.
   */
  const listen = async (reply: (path: string) => Reply) => {
    const received: Received[] = [];
    const server = createServer((request, response) => {
      let body = "";
      request.setEncoding("utf8");
      request.on("data", (chunk: string) => {
        body += chunk;
      });
      request.on("end", () => {
        received.push({ method: request.method, path: request.url, body });
        const { status, location, body: data } = reply(request.url ?? "");
        response.writeHead(status, location ? { Location: location } : {});
        response.end(data === undefined ? undefined : JSON.stringify(data));
      });
    });
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve)
    );
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("the local server has no port");
    }
    return { origin: `http://127.0.0.1:${address.port}`, received };
  };

  /** Sends what the connector sends to the account console to `origin` instead. */
  const routeAccountsTo = (origin: string) =>
    vi.stubGlobal("fetch", (url: string, init: RequestInit) =>
      realFetch(url.replace(ACCOUNTS_URL, origin), init)
    );

  const token = { access_token: "dbx-token", expires_in: 900 };

  it.each([307, 308])(
    "refuses a %i from the token endpoint, so the AWS identity token never reaches another host",
    async (status) => {
      const elsewhere = await listen(() => ({ status: 200, body: token }));
      const databricks = await listen((path) => ({
        status,
        location: `${elsewhere.origin}${path}`,
      }));
      routeAccountsTo(databricks.origin);

      await expect(
        newDatabricksClient(accountContext()).account({
          method: "GET",
          path: "/scim/v2/Users",
        })
      ).rejects.toMatchObject({ data: { type: "upstream_unavailable" } });

      expect(databricks.received).toEqual([
        expect.objectContaining({
          method: "POST",
          path: `/oidc/accounts/${ACCOUNT_ID}/v1/token`,
          body: expect.stringContaining(AWS_JWT),
        }),
      ]);
      expect(elsewhere.received).toEqual([]);
    }
  );

  it.each([307, 308])(
    "refuses a %i from an API call, so the call and its token never reach another host",
    async (status) => {
      const elsewhere = await listen(() => ({ status: 200, body: {} }));
      const databricks = await listen((path) =>
        path.startsWith("/oidc/")
          ? { status: 200, body: token }
          : { status, location: `${elsewhere.origin}${path}` }
      );
      routeAccountsTo(databricks.origin);

      await expect(
        newDatabricksClient(accountContext()).account({
          method: "PATCH",
          path: "/scim/v2/Users/1001",
          body: { Operations: [] },
        })
      ).rejects.toMatchObject({ data: { type: "upstream_unavailable" } });

      expect(databricks.received.map(({ path }) => path)).toEqual([
        `/oidc/accounts/${ACCOUNT_ID}/v1/token`,
        `/api/2.0/accounts/${ACCOUNT_ID}/scim/v2/Users/1001`,
      ]);
      expect(elsewhere.received).toEqual([]);
    }
  );
});
