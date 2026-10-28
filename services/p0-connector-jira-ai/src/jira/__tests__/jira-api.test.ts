import { ConnectorError } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/secret-manager-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  API,
  SITE,
  connectorErrorOf,
  fakeFetch,
  jsonResponse,
  logger,
  withoutWaits,
} from "../../__tests__/fixtures.ts";
import type { FakeSecretManager } from "../../__tests__/secret-manager-mock.ts";
import { REQUEST_BUDGET_MS } from "../atlassian-call.ts";
import { TOKEN_URL, forgetAllAdminTokens } from "../auth.ts";
import {
  addRoleActor,
  ensureSchemeGrants,
  fetchAccountIdByEmail,
  fetchProject,
  fetchProjectRoleIds,
  findOrCreateSiteRole,
  hasJiraAdmin,
  removeRoleActor,
  withJira,
} from "../jira-api.ts";

const vault = vi.hoisted((): { fake?: FakeSecretManager } => ({}));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => {
  const actual = await importOriginal<typeof SecretManagerClientModule>();
  const { fakeSecretManager } =
    await import("../../__tests__/secret-manager-mock.ts");
  const fake = fakeSecretManager(actual);
  vault.fake = fake;
  return {
    ...actual,
    createSecretManagerClient: fake.createSecretManagerClient,
  };
});

const fakeVault = () => {
  if (vault.fake === undefined)
    throw new Error("the secret manager isn't mocked");
  return vault.fake;
};

const secrets = () => fakeVault().secrets;

let net: ReturnType<typeof fakeFetch>;

beforeEach(() => {
  forgetAllAdminTokens();
  secrets().clear();
  secrets().set("acme-vault/jira-admin", "admin-secret");
  fakeVault().readDelay.ms = 0;
  net = fakeFetch();
  vi.stubGlobal("fetch", net.fetch);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const run = <T>(use: Parameters<typeof withJira<T>>[2]) =>
  withJira(SITE, logger, use);

describe("the admin token", () => {
  it("exchanges the admin client's credentials and sends the token to Jira", async () => {
    net.reply(`GET ${API}/project/ENG`, {
      status: 200,
      body: { id: "1", style: "classic" },
    });

    await run((jira) => fetchProject(jira, "ENG"));

    const [tokenUrl, tokenInit] = net.fetch.mock.calls[0]!;
    expect(tokenUrl).toBe(TOKEN_URL);
    expect(JSON.parse(tokenInit.body as string)).toEqual({
      grant_type: "client_credentials",
      client_id: "admin-client",
      client_secret: "admin-secret",
    });
    const [, apiInit] = net.fetch.mock.calls[1]!;
    expect(apiInit.headers).toMatchObject({
      Authorization: "Bearer admin-token-1",
    });
  });

  it("reuses the token until shortly before it expires, then mints another", async () => {
    vi.useFakeTimers({ now: 0 });
    net.reply(`GET ${API}/project/ENG`, {
      status: 200,
      body: { id: "1", style: "classic" },
    });
    const tokensUsed = () =>
      net.fetch.mock.calls
        .filter(([url]) => url !== TOKEN_URL)
        .map(
          ([, init]) => (init.headers as Record<string, string>).Authorization
        );

    await run((jira) => fetchProject(jira, "ENG"));
    vi.setSystemTime(3600_000 - 61_000);
    await run((jira) => fetchProject(jira, "ENG"));
    vi.setSystemTime(3600_000 - 59_000);
    await run((jira) => fetchProject(jira, "ENG"));

    expect(tokensUsed()).toEqual([
      "Bearer admin-token-1",
      "Bearer admin-token-1",
      "Bearer admin-token-2",
    ]);
  });

  it("caches per site", async () => {
    const other = { ...SITE, cloudId: "1e5a4f1e-2b7c-4c8d-9f10-3a4b5c6d7e8f" };
    net.reply(`GET ${API}/project/ENG`, {
      status: 200,
      body: { id: "1", style: "classic" },
    });
    net.reply(
      `GET https://api.atlassian.com/ex/jira/${other.cloudId}/rest/api/3/project/ENG`,
      { status: 200, body: { id: "1", style: "classic" } }
    );

    await run((jira) => fetchProject(jira, "ENG"));
    await withJira(other, logger, (jira) => fetchProject(jira, "ENG"));

    expect(net.calls().filter((call) => call.endsWith(TOKEN_URL))).toHaveLength(
      2
    );
  });

  it("drops the token when Jira refuses it, so the next call signs in again", async () => {
    net.reply(
      `GET ${API}/project/ENG`,
      { status: 401 },
      { status: 200, body: { id: "1", style: "classic" } }
    );

    await expect(run((jira) => fetchProject(jira, "ENG"))).rejects.toThrow();
    await run((jira) => fetchProject(jira, "ENG"));

    expect(net.calls().filter((call) => call.endsWith(TOKEN_URL))).toHaveLength(
      2
    );
  });

  it("reports refused client credentials without the secret", async () => {
    net.reply(`POST ${TOKEN_URL}`, {
      status: 401,
      body: { error: "access_denied", error_description: "admin-secret" },
    });

    const error = await connectorErrorOf(
      run((jira) => fetchProject(jira, "ENG"))
    );

    expect(error).toBeInstanceOf(ConnectorError);
    expect(error.data.type).toBe("insufficient_privileges");
    expect(error.message).toContain("access_denied");
    expect(JSON.stringify(error.data)).not.toContain("admin-secret");
  });

  it("reports a 400 invalid_client as refused client credentials", async () => {
    net.reply(`POST ${TOKEN_URL}`, {
      status: 400,
      body: { error: "invalid_client" },
    });

    const error = await connectorErrorOf(
      run((jira) => fetchProject(jira, "ENG"))
    );

    expect(error.data.type).toBe("insufficient_privileges");
    expect(error.message).toContain("refused the client credentials");
  });

  it("reports another 400 from the token endpoint as validation_error", async () => {
    net.reply(`POST ${TOKEN_URL}`, {
      status: 400,
      body: { error: "invalid_request" },
    });

    const error = await connectorErrorOf(
      run((jira) => fetchProject(jira, "ENG"))
    );

    expect(error.data.type).toBe("validation_error");
  });

  it("reports a missing admin secret without its name", async () => {
    secrets().clear();

    const error = await connectorErrorOf(
      run((jira) => fetchProject(jira, "ENG"))
    );

    expect(error.data.type).toBe("object_not_found");
    expect(JSON.stringify(error.data)).not.toContain("jira-admin");
  });

  it("stops waiting for the admin secret when the request's budget runs out", async () => {
    // The read would succeed, but only after the budget.
    fakeVault().readDelay.ms = REQUEST_BUDGET_MS + 5_000;

    const error = await withoutWaits(() =>
      connectorErrorOf(run((jira) => fetchProject(jira, "ENG")))
    );

    expect(error.data.type).toBe("upstream_unavailable");
    expect(error.message).toBe(
      "Google Secret Manager didn't return the Jira admin client secret in time. Try the request again in a few minutes."
    );
    expect(net.fetch).not.toHaveBeenCalled();
  });

  it("gives a slow admin secret read's time to the budget it shares with Atlassian", async () => {
    fakeVault().readDelay.ms = REQUEST_BUDGET_MS - 1_000;
    net.reply(`GET ${API}/project/ENG`, {
      status: 429,
      headers: { "Retry-After": "2" },
    });

    const error = await withoutWaits(() =>
      connectorErrorOf(run((jira) => fetchProject(jira, "ENG")))
    );

    // One second is left after the read, so the 2 s wait doesn't fit.
    expect(error.data.type).toBe("rate_limited");
    expect(net.calls().filter((call) => call.endsWith("/ENG"))).toHaveLength(1);
  });
});

describe("fetchAccountIdByEmail", () => {
  const search = `GET ${API}/user/search?query=a%40acme.com`;

  it("returns the one matching account", async () => {
    net.reply(search, {
      status: 200,
      body: [{ accountId: "acc-1", emailAddress: "A@acme.com" }],
    });

    await expect(
      run((jira) => fetchAccountIdByEmail(jira, "a@acme.com"))
    ).resolves.toBe("acc-1");
  });

  it("keeps an account that hides its email, and drops one with another email", async () => {
    net.reply(search, {
      status: 200,
      body: [
        { accountId: "acc-1" },
        { accountId: "acc-2", emailAddress: "a@acme.com.au" },
      ],
    });

    await expect(
      run((jira) => fetchAccountIdByEmail(jira, "a@acme.com"))
    ).resolves.toBe("acc-1");
  });

  // What Jira Cloud returns for an Atlassian service account.
  it("keeps an account whose email is empty", async () => {
    net.reply(search, {
      status: 200,
      body: [{ accountId: "acc-1", emailAddress: "" }],
    });

    await expect(
      run((jira) => fetchAccountIdByEmail(jira, "a@acme.com"))
    ).resolves.toBe("acc-1");
  });

  it.each([
    [0, []],
    [2, [{ accountId: "acc-1" }, { accountId: "acc-2" }]],
  ])("throws object_not_found on %i matches", async (count, body) => {
    net.reply(search, { status: 200, body });

    const error = await connectorErrorOf(
      run((jira) => fetchAccountIdByEmail(jira, "a@acme.com"))
    );

    expect(error.data).toMatchObject({
      type: "object_not_found",
      payload: { query: "a@acme.com", matches: count },
    });
  });

  it("keeps the search path and Jira's text out of a failure's message", async () => {
    net.reply(search, {
      status: 500,
      body: { errorMessages: ["bad query a@acme.com"] },
    });

    const error = await connectorErrorOf(
      withoutWaits(() =>
        run((jira) => fetchAccountIdByEmail(jira, "a@acme.com"))
      )
    );

    expect(error.data.type).toBe("upstream_unavailable");
    expect(error.message).not.toContain("a@acme.com");
    expect(error.message).not.toContain("/user/search");
  });
});

describe("paths", () => {
  it("encodes the project key and role id, on the fixed API host", async () => {
    net.reply(`GET ${API}/project/A%2FB/role`, { status: 200, body: {} });

    await run((jira) => fetchProjectRoleIds(jira, "A/B"));

    expect(net.calls()).toContain(`GET ${API}/project/A%2FB/role`);
  });

  it("asks Jira for the Administer Jira permission only", async () => {
    const permissions = `GET ${API}/mypermissions?permissions=ADMINISTER`;
    net.reply(permissions, {
      status: 200,
      body: { permissions: { ADMINISTER: { havePermission: true } } },
    });

    await expect(run((jira) => hasJiraAdmin(jira))).resolves.toBe(true);

    expect(net.calls()).toContain(permissions);
  });

  it("reads role ids from the role URLs", async () => {
    net.reply(`GET ${API}/project/ENG/role`, {
      status: 200,
      body: {
        Developers: `${API}/project/10000/role/10002`,
        "P0 Read": `${API}/project/10000/role/10100`,
        Odd: "not-a-url",
      },
    });

    await expect(
      run((jira) => fetchProjectRoleIds(jira, "ENG"))
    ).resolves.toEqual(
      new Map([
        ["Developers", "10002"],
        ["P0 Read", "10100"],
      ])
    );
  });
});

describe("site roles and scheme grants", () => {
  const grants = `${API}/permissionscheme/10050/permission`;

  it("reads Jira's numeric role ids as strings", async () => {
    net.reply(`GET ${API}/role`, {
      status: 200,
      body: [{ id: 10100, name: "P0 agent: read", description: "x" }],
    });

    await expect(
      run((jira) => findOrCreateSiteRole(jira, "P0 agent: read", "x"))
    ).resolves.toEqual({
      id: "10100",
      name: "P0 agent: read",
      description: "x",
    });
    expect(net.calls()).not.toContain(`POST ${API}/role`);
  });

  it("fails a refused create when the role still isn't there", async () => {
    net.reply(`GET ${API}/role`, { status: 200, body: [] });
    net.reply(`POST ${API}/role`, {
      status: 400,
      body: { errors: { name: "The name is too long." } },
    });

    await expect(
      run((jira) => findOrCreateSiteRole(jira, "P0 agent: read", "x"))
    ).rejects.toMatchObject({ data: { type: "validation_error" } });
  });

  it("counts a grant whose holder names the role in parameter only", async () => {
    net.reply(`GET ${API}/project/ENG/permissionscheme`, {
      status: 200,
      body: { id: 10050, name: "Default" },
    });
    net.reply(`GET ${grants}`, {
      status: 200,
      body: {
        permissions: [
          {
            id: 1,
            holder: { type: "projectRole", parameter: "10100" },
            permission: "BROWSE_PROJECTS",
          },
          // A grant to everyone, with no role.
          { id: 2, holder: { type: "anyone" }, permission: "ADD_COMMENTS" },
        ],
      },
    });
    net.reply(`POST ${grants}`, { status: 201, body: { id: 3 } });

    await expect(
      run((jira) =>
        ensureSchemeGrants(jira, "ENG", "10100", [
          "BROWSE_PROJECTS",
          "ADD_COMMENTS",
        ])
      )
    ).resolves.toBe(1);
    expect(net.calls()).toContain(`POST ${grants}`);
  });

  describe("a grant Jira refuses as already present", () => {
    const browse = {
      id: 1,
      holder: { type: "projectRole", parameter: "10100", value: "10100" },
      permission: "BROWSE_PROJECTS",
    };
    const refused = {
      status: 400,
      body: { errorMessages: ["The same permission grant is present."] },
    };

    beforeEach(() => {
      net.reply(`GET ${API}/project/ENG/permissionscheme`, {
        status: 200,
        body: { id: 10050 },
      });
      net.reply(`POST ${grants}`, refused);
    });

    it("counts as done when the scheme then shows it", async () => {
      net.reply(
        `GET ${grants}`,
        { status: 200, body: { permissions: [] } },
        { status: 200, body: { permissions: [browse] } }
      );

      await expect(
        run((jira) =>
          ensureSchemeGrants(jira, "ENG", "10100", ["BROWSE_PROJECTS"])
        )
      ).resolves.toBe(1);
    });

    it("fails when the scheme still lacks it", async () => {
      net.reply(`GET ${grants}`, { status: 200, body: { permissions: [] } });

      await expect(
        run((jira) =>
          ensureSchemeGrants(jira, "ENG", "10100", ["BROWSE_PROJECTS"])
        )
      ).rejects.toMatchObject({ data: { type: "validation_error" } });
    });
  });
});

describe("retries", () => {
  it("retries a role add that Jira answered with a 503", async () => {
    const role = `${API}/project/ENG/role/10100`;
    net.reply(`POST ${role}`, { status: 503 }, { status: 200, body: {} });

    await withoutWaits(() =>
      run((jira) => addRoleActor(jira, "ENG", "10100", "acc-1"))
    );

    expect(net.calls().filter((call) => call === `POST ${role}`)).toHaveLength(
      2
    );
  });

  it("retries the admin token exchange on a 429", async () => {
    net.reply(
      `POST ${TOKEN_URL}`,
      { status: 429, headers: { "Retry-After": "1" } },
      { status: 200, body: { access_token: "fresh", expires_in: 3600 } }
    );
    net.reply(`GET ${API}/project/ENG`, {
      status: 200,
      body: { id: "1", style: "classic" },
    });

    await withoutWaits(() => run((jira) => fetchProject(jira, "ENG")));

    expect(net.fetch.mock.calls[2]?.[1].headers).toMatchObject({
      Authorization: "Bearer fresh",
    });
  });
});

describe("role actors", () => {
  const role = `${API}/project/ENG/role/10100`;

  it("adds with a POST of the account, never a PUT", async () => {
    net.reply(`POST ${role}`, { status: 200, body: {} });

    await run((jira) => addRoleActor(jira, "ENG", "10100", "acc-1"));

    const [, init] = net.fetch.mock.calls[1]!;
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ user: ["acc-1"] });
    expect(net.calls().some((call) => call.startsWith("PUT"))).toBe(false);
  });

  it("removes with a DELETE that names the account", async () => {
    net.reply(`DELETE ${role}?user=acc-1`, { status: 204 });

    await run((jira) => removeRoleActor(jira, "ENG", "10100", "acc-1"));

    expect(net.calls()).toContain(`DELETE ${role}?user=acc-1`);
  });

  it("succeeds on a repeated add that Jira refuses because the account already holds the role", async () => {
    net.reply(
      `POST ${role}`,
      { status: 200, body: {} },
      { status: 400, body: { errorMessages: ["already a member"] } }
    );
    net.reply(`GET ${role}`, {
      status: 200,
      body: { actors: [{ actorUser: { accountId: "acc-1" } }] },
    });

    await run((jira) => addRoleActor(jira, "ENG", "10100", "acc-1"));
    await run((jira) => addRoleActor(jira, "ENG", "10100", "acc-1"));
  });

  it("fails an add that Jira refuses when the account doesn't hold the role", async () => {
    net.reply(`POST ${role}`, {
      status: 400,
      body: { errorMessages: ["user is inactive"] },
    });
    net.reply(`GET ${role}`, { status: 200, body: { actors: [] } });

    const error = await connectorErrorOf(
      run((jira) => addRoleActor(jira, "ENG", "10100", "acc-1"))
    );

    expect(error.data.type).toBe("validation_error");
    expect(error.message).toContain("user is inactive");
  });

  it("reports Jira's refusal when the role can't be read back", async () => {
    net.reply(`POST ${role}`, {
      status: 400,
      body: { errorMessages: ["user is inactive"] },
    });
    net.reply(`GET ${role}`, { status: 403 });

    const error = await connectorErrorOf(
      run((jira) => addRoleActor(jira, "ENG", "10100", "acc-1"))
    );

    expect(error.data).toMatchObject({
      type: "validation_error",
      payload: { status: 400 },
    });
  });

  it("succeeds on a repeated remove, whether Jira answers 404 or 400", async () => {
    net.reply(
      `DELETE ${role}?user=acc-1`,
      { status: 204 },
      { status: 404 },
      { status: 400 }
    );
    net.reply(`GET ${role}`, { status: 200, body: { actors: [] } });
    net.reply(`GET ${API}/mypermissions?permissions=ADMINISTER`, {
      status: 200,
      body: { permissions: { ADMINISTER: { havePermission: true } } },
    });

    await run((jira) => removeRoleActor(jira, "ENG", "10100", "acc-1"));
    await run((jira) => removeRoleActor(jira, "ENG", "10100", "acc-1"));
    await run((jira) => removeRoleActor(jira, "ENG", "10100", "acc-1"));
  });

  it("refuses to count a 404 as removed once the admin account has lost Administer Jira", async () => {
    net.reply(`DELETE ${role}?user=acc-1`, { status: 404 });
    net.reply(`GET ${API}/mypermissions?permissions=ADMINISTER`, {
      status: 200,
      body: { permissions: { ADMINISTER: { havePermission: false } } },
    });

    const error = await connectorErrorOf(
      run((jira) => removeRoleActor(jira, "ENG", "10100", "acc-1"))
    );

    expect(error.data).toMatchObject({
      type: "insufficient_privileges",
      payload: { projectKey: "ENG" },
    });
  });
});

describe("failures", () => {
  it("maps an answer of an unexpected shape to unknown, without quoting it", async () => {
    net.reply(`GET ${API}/project/ENG`, {
      status: 200,
      body: { style: ["classic"], secret: "do-not-quote" },
    });

    const error = await connectorErrorOf(
      run((jira) => fetchProject(jira, "ENG"))
    );

    expect(error).toBeInstanceOf(ConnectorError);
    expect(error.data.type).toBe("unknown");
    expect(JSON.stringify(error.data)).not.toContain("do-not-quote");
  });

  it.each([
    [400, "validation_error"],
    [401, "insufficient_privileges"],
    [403, "insufficient_privileges"],
    [404, "object_not_found"],
    [429, "rate_limited"],
    [500, "upstream_unavailable"],
    [503, "upstream_unavailable"],
    [409, "unknown"],
  ])("maps Jira's %i to %s", async (status, type) => {
    net.reply(`GET ${API}/project/ENG`, {
      status,
      body: { errorMessages: ["nope"] },
    });

    const error = await connectorErrorOf(
      withoutWaits(() => run((jira) => fetchProject(jira, "ENG")))
    );

    expect(error).toBeInstanceOf(ConnectorError);
    expect(error.data).toMatchObject({
      type,
      payload: { status },
    });
  });

  it("maps a network failure to upstream_unavailable", async () => {
    net.fetch.mockImplementation(async (url: string) => {
      if (url === TOKEN_URL)
        return jsonResponse({
          status: 200,
          body: { access_token: "t", expires_in: 3600 },
        });
      throw new TypeError("fetch failed");
    });

    const error = await connectorErrorOf(
      withoutWaits(() => run((jira) => fetchProject(jira, "ENG")))
    );

    expect(error.data.type).toBe("upstream_unavailable");
  });

  it("never quotes the admin token", async () => {
    net.reply(`GET ${API}/project/ENG`, { status: 403 });

    const error = await connectorErrorOf(
      run((jira) => fetchProject(jira, "ENG"))
    );

    expect(JSON.stringify(error.data)).not.toContain("admin-token");
  });
});
