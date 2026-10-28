import type * as SecretManagerClientModule from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  API,
  SITE,
  connectorErrorOf,
  fakeFetch,
  logger,
} from "../../__tests__/fixtures.ts";
import type { FakeSecretManager } from "../../__tests__/secret-manager-mock.ts";
import { p0RoleDescription } from "../../accesses/role/p0-roles.ts";
import { forgetAllAdminTokens } from "../../jira/auth.ts";
import { connectorRouter } from "../../router.ts";

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

const { install } = connectorRouter.createCaller({ logger })["jira-ai"];

let net: ReturnType<typeof fakeFetch>;

beforeEach(() => {
  forgetAllAdminTokens();
  const { secrets } = fakeVault();
  secrets.clear();
  secrets.set("acme-vault/jira-admin", "admin-secret");
  net = fakeFetch();
  vi.stubGlobal("fetch", net.fetch);
});

describe("install.site.get", () => {
  const permissions = `GET ${API}/mypermissions?permissions=ADMINISTER`;
  const get = () => install.site.get({ site: SITE });
  const administer = (havePermission: boolean) => ({
    permissions: {
      ADMINISTER: {
        id: "0",
        key: "ADMINISTER",
        name: "Administer Jira",
        type: "GLOBAL",
        havePermission,
      },
    },
  });

  const siteRoles = `GET ${API}/role`;
  const p0Role = (name: string, tenantId?: string) => ({
    id: name.endsWith("read") ? 10100 : 10101,
    name,
    description:
      tenantId === undefined ? undefined : p0RoleDescription(tenantId),
  });

  const createRole = `POST ${API}/role`;
  const createdRoles = () => net.posted(`${API}/role`);

  beforeEach(() => {
    net.reply(siteRoles, {
      status: 200,
      body: [{ id: 10002, name: "Administrators" }],
    });
    net.reply(
      createRole,
      { status: 201, body: p0Role("P0 agent: read", "acme") },
      { status: 201, body: p0Role("P0 agent: write", "acme") }
    );
  });

  it("claims the site by creating both P0 roles for this organization", async () => {
    net.reply(permissions, { status: 200, body: administer(true) });

    await expect(get()).resolves.toEqual({ jiraAdmin: true });
    expect(createdRoles()).toEqual([
      { name: "P0 agent: read", description: p0RoleDescription("acme") },
      { name: "P0 agent: write", description: p0RoleDescription("acme") },
    ]);
  });

  it("reports an admin account without Administer Jira, without reading the roles", async () => {
    net.reply(permissions, { status: 200, body: administer(false) });

    await expect(get()).resolves.toEqual({ jiraAdmin: false });
    expect(net.calls()).not.toContain(siteRoles);
  });

  it("accepts P0 roles this organization manages, without changing them", async () => {
    net.reply(permissions, { status: 200, body: administer(true) });
    net.reply(siteRoles, {
      status: 200,
      body: [
        p0Role("P0 agent: read", "acme"),
        p0Role("P0 agent: write", "acme"),
      ],
    });

    await expect(get()).resolves.toEqual({ jiraAdmin: true });
    expect(
      net.calls().filter((call) => call.startsWith(`POST ${API}`))
    ).toEqual([]);
  });

  it.each([
    ["names no organization", p0Role("P0 agent: write")],
    [
      "doesn't start with P0's description",
      {
        id: 10101,
        name: "P0 agent: write",
        description: "Our writers. P0 organization: acme",
      },
    ],
  ])(
    "refuses a role with P0's name whose description %s, and tells an admin to rename or delete it",
    async (_, role) => {
      net.reply(permissions, { status: 200, body: administer(true) });
      net.reply(siteRoles, {
        status: 200,
        body: [p0Role("P0 agent: read", "acme"), role],
      });

      const failure = await connectorErrorOf(get());

      expect(failure.data).toMatchObject({
        type: "validation_error",
        payload: { roleId: "10101" },
      });
      expect(failure.message).toContain(
        'named "P0 agent: write" that P0 didn\'t make for this organization'
      );
      expect(failure.message).toContain("rename or delete that role");
      expect(net.calls()).not.toContain(`POST ${API}/role/10101`);
    }
  );

  it("refuses a site whose P0 roles another organization manages", async () => {
    net.reply(permissions, { status: 200, body: administer(true) });
    net.reply(siteRoles, {
      status: 200,
      body: [p0Role("P0 agent: read", "globex")],
    });

    const failure = await connectorErrorOf(get());

    expect(failure.data.type).toBe("validation_error");
    expect(failure.message).toContain("only one organization can");
    expect(createdRoles()).toEqual([]);
  });

  it("reports a missing ADMINISTER entry as no Administer Jira", async () => {
    net.reply(permissions, { status: 200, body: { permissions: {} } });

    await expect(get()).resolves.toEqual({ jiraAdmin: false });
  });

  it("fails with insufficient_privileges when Jira refuses the token, without quoting it", async () => {
    net.reply(permissions, { status: 401 });

    const { data: failure } = await connectorErrorOf(get());

    expect(failure).toMatchObject({
      type: "insufficient_privileges",
      payload: { status: 401 },
    });
    expect(JSON.stringify(failure)).not.toContain("admin-token");
  });
});

describe("install.account.get", () => {
  const search = `GET ${API}/user/search?query=pool-1%40acme.com`;
  const get = () =>
    install.account.get({ site: SITE, email: "pool-1@acme.com" });

  it("returns the account id of the one match", async () => {
    net.reply(search, {
      status: 200,
      body: [{ accountId: "acc-1", emailAddress: "pool-1@acme.com" }],
    });

    await expect(get()).resolves.toEqual({ accountId: "acc-1" });
  });

  it("fails with object_not_found and the email when nothing matches", async () => {
    net.reply(search, { status: 200, body: [] });

    await expect(connectorErrorOf(get())).resolves.toMatchObject({
      data: {
        type: "object_not_found",
        payload: { query: "pool-1@acme.com", matches: 0 },
      },
    });
  });

  it("fails with object_not_found when two accounts match", async () => {
    net.reply(search, {
      status: 200,
      body: [{ accountId: "acc-1" }, { accountId: "acc-2" }],
    });

    await expect(connectorErrorOf(get())).resolves.toMatchObject({
      data: {
        type: "object_not_found",
        payload: { query: "pool-1@acme.com", matches: 2 },
      },
    });
  });

  it("refuses a site whose cloud id isn't a UUID, before calling anything", async () => {
    await expect(
      install.account.get({
        site: { ...SITE, cloudId: "evil.example.com" },
        email: "a@acme.com",
      })
    ).rejects.toThrow();
    expect(net.fetch).not.toHaveBeenCalled();
  });
});

describe("install.project.get", () => {
  const get = () => install.project.get({ site: SITE, projectKey: "ENG" });
  const replyProject = (style: string, roles: Record<string, string>) => {
    net.reply(`GET ${API}/project/ENG`, {
      status: 200,
      body: { id: "10000", style },
    });
    net.reply(`GET ${API}/project/ENG/role`, { status: 200, body: roles });
  };

  it("reports a company-managed project and its roles", async () => {
    replyProject("classic", {
      Administrators: `${API}/project/10000/role/10002`,
      "P0 agent: read": `${API}/project/10000/role/10100`,
    });

    await expect(get()).resolves.toEqual({
      style: "company-managed",
      roles: [
        { id: "10002", name: "Administrators" },
        { id: "10100", name: "P0 agent: read" },
      ],
    });
  });

  it("reports a team-managed project and its own roles", async () => {
    replyProject("next-gen", {
      Administrator: `${API}/project/10000/role/10202`,
      Member: `${API}/project/10000/role/10201`,
      Viewer: `${API}/project/10000/role/10200`,
    });

    await expect(get()).resolves.toEqual({
      style: "team-managed",
      roles: [
        { id: "10202", name: "Administrator" },
        { id: "10201", name: "Member" },
        { id: "10200", name: "Viewer" },
      ],
    });
  });

  it("reports a project with no roles", async () => {
    replyProject("next-gen", {});

    await expect(get()).resolves.toEqual({ style: "team-managed", roles: [] });
  });

  it("fails with object_not_found for a project Jira doesn't show the admin", async () => {
    net.reply(`GET ${API}/project/ENG`, { status: 404 });

    await expect(connectorErrorOf(get())).resolves.toMatchObject({
      data: { type: "object_not_found", payload: { status: 404 } },
    });
  });
});
