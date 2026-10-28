import { ConnectorError } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  API,
  CLOUD_ID,
  SITE,
  connectorErrorOf,
  fakeFetch,
  logger,
  withoutWaits,
} from "../../../__tests__/fixtures.ts";
import type { FakeSecretManager } from "../../../__tests__/secret-manager-mock.ts";
import { REQUEST_BUDGET_MS } from "../../../jira/atlassian-call.ts";
import { forgetAllAdminTokens } from "../../../jira/auth.ts";
import { t } from "../../../router.ts";
import { P0_ROLES, type RolePolicy } from "../definition.ts";
import { router } from "../handler.ts";
import { P0_ROLE_DESCRIPTION, p0RoleDescription } from "../p0-roles.ts";

const vault = vi.hoisted((): { fake?: FakeSecretManager } => ({}));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => {
  const actual = await importOriginal<typeof SecretManagerClientModule>();
  const { fakeSecretManager } =
    await import("../../../__tests__/secret-manager-mock.ts");
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

const caller = () => router(t).createCaller({ logger });

const context = {
  requestId: "r-1",
  site: SITE,
  projectKey: "ENG",
  roleIds: [],
};

const PERMISSIONS = `${API}/mypermissions?permissions=ADMINISTER`;
const PROJECT_ROLES = `${API}/project/ENG/role`;
const SITE_ROLES = `${API}/role`;
const SCHEME = `${API}/project/ENG/permissionscheme`;
const GRANTS = `${API}/permissionscheme/10050/permission`;

// P0's roles, as the site and a company-managed project list them.
const READ_ID = "10100";
const WRITE_ID = "10101";
const READ = `${API}/project/ENG/role/${READ_ID}`;
const WRITE = `${API}/project/ENG/role/${WRITE_ID}`;
// A team-managed project's Viewer and Member roles.
const VIEWER = `${API}/project/ENG/role/10200`;
const MEMBER = `${API}/project/ENG/role/10201`;

const WRITE_PERMISSIONS = P0_ROLES.write.permissions;

// The descriptions of P0 roles this tenant and another one manage.
const OURS = p0RoleDescription("acme");
const THEIRS = p0RoleDescription("globex");

const replyAdmin = (havePermission: boolean) =>
  net.reply(`GET ${PERMISSIONS}`, {
    status: 200,
    body: { permissions: { ADMINISTER: { havePermission } } },
  });

const grantOf = (roleId: number, permission: string) => ({
  id: 1,
  holder: {
    type: "projectRole",
    parameter: String(roleId),
    value: String(roleId),
  },
  permission,
});

const replyGrants = (...grants: ReturnType<typeof grantOf>[]) =>
  net.reply(`GET ${GRANTS}`, { status: 200, body: { permissions: grants } });

let net: ReturnType<typeof fakeFetch>;

beforeEach(() => {
  forgetAllAdminTokens();
  const { secrets } = fakeVault();
  secrets.clear();
  secrets.set("acme-vault/jira-admin", "admin-secret");
  net = fakeFetch();
  vi.stubGlobal("fetch", net.fetch);
  net.reply(`GET ${PROJECT_ROLES}`, {
    status: 200,
    body: {
      Administrators: `${API}/project/10000/role/10002`,
      "P0 agent: read": `${API}/project/10000/role/${READ_ID}`,
      "P0 agent: write": `${API}/project/10000/role/${WRITE_ID}`,
    },
  });
  net.reply(`GET ${SITE_ROLES}`, {
    status: 200,
    body: [
      { id: 10002, name: "Administrators" },
      { id: Number(READ_ID), name: "P0 agent: read", description: OURS },
      { id: Number(WRITE_ID), name: "P0 agent: write", description: OURS },
    ],
  });
  net.reply(`GET ${SCHEME}`, { status: 200, body: { id: 10050 } });
  replyGrants(
    grantOf(10100, "BROWSE_PROJECTS"),
    ...WRITE_PERMISSIONS.map((permission) => grantOf(10101, permission))
  );
  net.reply(`POST ${GRANTS}`, { status: 201, body: { id: 2 } });
  for (const role of [READ, WRITE, VIEWER, MEMBER]) {
    net.reply(`POST ${role}`, { status: 200, body: {} });
    net.reply(`DELETE ${role}?user=acc-1`, { status: 204 });
  }
});

const setPolicies = (policies: RolePolicy[], roleIds: string[] = []) =>
  caller().setPoliciesForUser({
    userId: "acc-1",
    userBody: { cloudId: CLOUD_ID, accountId: "acc-1" },
    policies,
    context: { ...context, roleIds },
  });

const read: RolePolicy = { type: "p0", level: "read" };
const write: RolePolicy = { type: "p0", level: "write" };

const jiraCalls = () =>
  net.calls().filter((call) => !call.includes("auth.atlassian.com"));

const teamManagedRoles = () =>
  net.reply(`GET ${PROJECT_ROLES}`, {
    status: 200,
    body: {
      Administrator: `${API}/project/10000/role/10202`,
      Member: `${API}/project/10000/role/10201`,
      Viewer: `${API}/project/10000/role/10200`,
    },
  });

describe("provisionUser", () => {
  it("echoes the account id for a body on the request's site", async () => {
    await expect(
      caller().provisionUser({
        userBody: { cloudId: CLOUD_ID, accountId: "acc-1" },
        context,
      })
    ).resolves.toBe("acc-1");
    expect(net.fetch).not.toHaveBeenCalled();
  });

  it("refuses a body for another site", async () => {
    await expect(
      caller().provisionUser({
        userBody: {
          cloudId: "1e5a4f1e-2b7c-4c8d-9f10-3a4b5c6d7e8f",
          accountId: "acc-1",
        },
        context,
      })
    ).rejects.toBeInstanceOf(ConnectorError);
  });
});

describe("setPoliciesForUser, company-managed", () => {
  it("adds the account to P0's read role and removes it from P0's write role", async () => {
    await setPolicies([read]);

    expect(jiraCalls()).toEqual([
      `GET ${PROJECT_ROLES}`,
      `GET ${SITE_ROLES}`,
      `GET ${SCHEME}`,
      `GET ${GRANTS}`,
      `POST ${READ}`,
      `DELETE ${WRITE}?user=acc-1`,
    ]);
    expect(net.posted(READ)).toEqual([{ user: ["acc-1"] }]);
  });

  it("adds the account to P0's write role and removes it from P0's read role", async () => {
    await setPolicies([write]);

    expect(jiraCalls()).toEqual([
      `GET ${PROJECT_ROLES}`,
      `GET ${SITE_ROLES}`,
      `GET ${SCHEME}`,
      `GET ${GRANTS}`,
      `POST ${WRITE}`,
      `DELETE ${READ}?user=acc-1`,
    ]);
  });

  it("creates both of P0's roles when the site has none, and grants the kept one its permissions in the scheme", async () => {
    net.reply(`GET ${SITE_ROLES}`, {
      status: 200,
      body: [{ id: 10002, name: "Administrators" }],
    });
    net.reply(
      `POST ${SITE_ROLES}`,
      {
        status: 200,
        body: { id: 10299, name: "P0 agent: read", description: OURS },
      },
      {
        status: 200,
        body: { id: 10300, name: "P0 agent: write", description: OURS },
      }
    );
    replyGrants();
    net.reply(`POST ${API}/project/ENG/role/10300`, { status: 200, body: {} });

    await setPolicies([write]);

    expect(net.posted(SITE_ROLES)).toEqual([
      {
        name: "P0 agent: read",
        description: `${P0_ROLE_DESCRIPTION} P0 organization: acme`,
      },
      {
        name: "P0 agent: write",
        description: `${P0_ROLE_DESCRIPTION} P0 organization: acme`,
      },
    ]);
    expect(jiraCalls()).not.toContain(`POST ${SITE_ROLES}/10300`);
    expect(net.posted(GRANTS)).toEqual(
      WRITE_PERMISSIONS.map((permission) => ({
        holder: { type: "projectRole", value: "10300" },
        permission,
      }))
    );
    expect(jiraCalls()).toContain(`POST ${API}/project/ENG/role/10300`);
  });

  it("reuses roles a parallel grant created between the list and the create", async () => {
    net.reply(
      `GET ${SITE_ROLES}`,
      { status: 200, body: [] },
      {
        status: 200,
        body: [
          { id: Number(READ_ID), name: "P0 agent: read", description: OURS },
          { id: Number(WRITE_ID), name: "P0 agent: write", description: OURS },
        ],
      }
    );
    net.reply(`POST ${SITE_ROLES}`, {
      status: 409,
      body: {
        errorMessages: ["A project role with that name already exists."],
      },
    });

    await setPolicies([read]);

    expect(jiraCalls()).toContain(`POST ${READ}`);
  });

  it("grants only the permissions the scheme lacks", async () => {
    replyGrants(
      grantOf(10101, "BROWSE_PROJECTS"),
      grantOf(10101, "ADD_COMMENTS"),
      // Another role's grant doesn't count for P0's.
      grantOf(10002, "CREATE_ISSUES")
    );

    await setPolicies([write]);

    expect(net.posted(GRANTS)).toEqual(
      WRITE_PERMISSIONS.filter(
        (permission) =>
          permission !== "BROWSE_PROJECTS" && permission !== "ADD_COMMENTS"
      ).map((permission) => ({
        holder: { type: "projectRole", value: WRITE_ID },
        permission,
      }))
    );
  });

  it("adds the newer write permissions to a scheme that holds the first five", async () => {
    const firstFive = [
      "BROWSE_PROJECTS",
      "ADD_COMMENTS",
      "CREATE_ISSUES",
      "EDIT_ISSUES",
      "TRANSITION_ISSUES",
    ];
    replyGrants(...firstFive.map((permission) => grantOf(10101, permission)));

    await setPolicies([write]);

    expect(net.posted(GRANTS)).toEqual(
      WRITE_PERMISSIONS.filter(
        (permission) => !firstFive.includes(permission)
      ).map((permission) => ({
        holder: { type: "projectRole", value: WRITE_ID },
        permission,
      }))
    );
  });

  it("grants nothing in the scheme when every permission is there", async () => {
    await setPolicies([write]);

    expect(net.posted(GRANTS)).toEqual([]);
  });

  it("removes the account from both of P0's roles when no policy remains, without touching the scheme", async () => {
    await setPolicies([]);

    expect(jiraCalls()).toEqual([
      `GET ${PROJECT_ROLES}`,
      `GET ${SITE_ROLES}`,
      `DELETE ${READ}?user=acc-1`,
      `DELETE ${WRITE}?user=acc-1`,
    ]);
  });

  it("removes the account from a P0 role an admin renamed, found by its description", async () => {
    net.reply(`GET ${PROJECT_ROLES}`, {
      status: 200,
      body: {
        Administrators: `${API}/project/10000/role/10002`,
        "P0 agent: read": `${API}/project/10000/role/${READ_ID}`,
        "Agent writers": `${API}/project/10000/role/${WRITE_ID}`,
      },
    });
    net.reply(`GET ${SITE_ROLES}`, {
      status: 200,
      body: [
        { id: 10002, name: "Administrators", description: "Admins" },
        {
          id: Number(READ_ID),
          name: "P0 agent: read",
          description: P0_ROLE_DESCRIPTION,
        },
        {
          id: Number(WRITE_ID),
          name: "Agent writers",
          description: P0_ROLE_DESCRIPTION,
        },
      ],
    });

    await setPolicies([]);

    expect(jiraCalls()).toEqual([
      `GET ${PROJECT_ROLES}`,
      `GET ${SITE_ROLES}`,
      `DELETE ${READ}?user=acc-1`,
      `DELETE ${WRITE}?user=acc-1`,
    ]);
  });

  it("removes the account from a renamed P0 role when it grants the other one", async () => {
    net.reply(`GET ${SITE_ROLES}`, {
      status: 200,
      body: [
        { id: Number(READ_ID), name: "P0 agent: read", description: OURS },
        { id: Number(WRITE_ID), name: "Agent writers", description: OURS },
      ],
    });
    // The rename frees P0's name, so the claim makes a new write role.
    net.reply(`POST ${SITE_ROLES}`, {
      status: 200,
      body: { id: 10301, name: "P0 agent: write", description: OURS },
    });

    await setPolicies([read]);

    expect(jiraCalls()).toContain(`DELETE ${WRITE}?user=acc-1`);
  });

  it("removes the account from P0's site roles that the project's role list leaves out", async () => {
    net.reply(`GET ${PROJECT_ROLES}`, {
      status: 200,
      body: { Administrators: `${API}/project/10000/role/10002` },
    });

    await setPolicies([]);

    expect(jiraCalls()).toEqual([
      `GET ${PROJECT_ROLES}`,
      `GET ${SITE_ROLES}`,
      `DELETE ${READ}?user=acc-1`,
      `DELETE ${WRITE}?user=acc-1`,
    ]);
  });

  it("never touches a role P0 neither keeps nor recorded", async () => {
    await setPolicies([read]);
    await setPolicies([]);

    expect(jiraCalls().some((call) => call.includes("/role/10002"))).toBe(
      false
    );
  });

  it("never sends a PUT", async () => {
    await setPolicies([write]);
    await setPolicies([]);

    expect(net.calls().some((call) => call.startsWith("PUT"))).toBe(false);
  });

  it("fails when Jira refuses a scheme grant, before adding the account", async () => {
    replyGrants();
    net.reply(`POST ${GRANTS}`, {
      status: 403,
      body: { errorMessages: ["You can't edit this scheme."] },
    });

    await expect(setPolicies([read])).rejects.toMatchObject({
      data: { type: "insufficient_privileges" },
    });
    expect(jiraCalls()).not.toContain(`POST ${READ}`);
  });
});

describe("setPoliciesForUser, one P0 organization per site", () => {
  const replySiteRoles = (
    readDescription?: string,
    writeDescription?: string
  ) =>
    net.reply(`GET ${SITE_ROLES}`, {
      status: 200,
      body: [
        { id: 10002, name: "Administrators" },
        {
          id: Number(READ_ID),
          name: "P0 agent: read",
          description: readDescription,
        },
        {
          id: Number(WRITE_ID),
          name: "P0 agent: write",
          description: writeDescription,
        },
      ],
    });

  it.each([
    ["names no organization", P0_ROLE_DESCRIPTION],
    ["has no description", undefined],
    ["doesn't start with P0's description", "Readers. P0 organization: acme"],
  ])(
    "refuses a role with P0's name whose description %s, and changes nothing",
    async (_, description) => {
      replySiteRoles(description, OURS);

      const error = await connectorErrorOf(setPolicies([read]));

      expect(error).toMatchObject({
        data: { type: "validation_error", payload: { roleId: READ_ID } },
      });
      expect(error.message).toContain(
        "Ask a Jira admin to rename or delete that role under Settings > System > Project roles"
      );
      expect(jiraCalls().filter((call) => !call.startsWith("GET"))).toEqual([]);
    }
  );

  it("refuses a team-managed grant when a role with P0's name isn't P0's", async () => {
    teamManagedRoles();
    replySiteRoles(OURS, "Writers made by hand");

    await expect(
      setPolicies([{ type: "space", roleId: "10200" }], ["10200"])
    ).rejects.toMatchObject({ data: { type: "validation_error" } });
    expect(jiraCalls()).not.toContain(`POST ${VIEWER}`);
  });

  it("still removes the account from a role with P0's name that isn't P0's", async () => {
    replySiteRoles(undefined, undefined);

    await setPolicies([]);

    expect(jiraCalls()).toEqual([
      `GET ${PROJECT_ROLES}`,
      `GET ${SITE_ROLES}`,
      `DELETE ${READ}?user=acc-1`,
      `DELETE ${WRITE}?user=acc-1`,
    ]);
  });

  it("refuses a grant when another organization manages the role", async () => {
    replySiteRoles(THEIRS, THEIRS);

    const error = await connectorErrorOf(setPolicies([read]));

    expect(error).toMatchObject({ data: { type: "validation_error" } });
    expect(error.message).toContain(
      "Another P0 organization already manages this Jira site's P0 roles"
    );
    expect(jiraCalls().filter((call) => !call.startsWith("GET"))).toEqual([]);
  });

  it("refuses a grant when another organization manages the other P0 role", async () => {
    replySiteRoles(OURS, THEIRS);

    await expect(setPolicies([read])).rejects.toMatchObject({
      data: { type: "validation_error" },
    });
    expect(jiraCalls()).not.toContain(`POST ${READ}`);
  });

  it("refuses a role another organization created in parallel", async () => {
    net.reply(
      `GET ${SITE_ROLES}`,
      { status: 200, body: [] },
      {
        status: 200,
        body: [
          { id: Number(READ_ID), name: "P0 agent: read", description: THEIRS },
        ],
      }
    );
    net.reply(`POST ${SITE_ROLES}`, {
      status: 409,
      body: {
        errorMessages: ["A project role with that name already exists."],
      },
    });

    await expect(setPolicies([read])).rejects.toMatchObject({
      data: { type: "validation_error" },
    });
    expect(jiraCalls()).not.toContain(`POST ${READ}`);
  });

  it("still removes the account when another organization manages the roles", async () => {
    replySiteRoles(THEIRS, THEIRS);

    await setPolicies([]);

    expect(jiraCalls()).toEqual([
      `GET ${PROJECT_ROLES}`,
      `GET ${SITE_ROLES}`,
      `DELETE ${READ}?user=acc-1`,
      `DELETE ${WRITE}?user=acc-1`,
    ]);
  });

  it("finds a renamed P0 role by the start of its description", async () => {
    net.reply(`GET ${PROJECT_ROLES}`, {
      status: 200,
      body: { Administrators: `${API}/project/10000/role/10002` },
    });
    net.reply(`GET ${SITE_ROLES}`, {
      status: 200,
      body: [
        { id: 10002, name: "Administrators" },
        { id: Number(WRITE_ID), name: "Agent writers", description: OURS },
      ],
    });

    await setPolicies([]);

    expect(jiraCalls()).toContain(`DELETE ${WRITE}?user=acc-1`);
  });
});

describe("setPoliciesForUser, team-managed", () => {
  beforeEach(teamManagedRoles);

  it("adds the account to the requested space role by id, and nothing else", async () => {
    await setPolicies([{ type: "space", roleId: "10200" }], ["10200"]);

    expect(jiraCalls()).toEqual([
      `GET ${PROJECT_ROLES}`,
      `GET ${SITE_ROLES}`,
      `POST ${VIEWER}`,
    ]);
    expect(net.posted(VIEWER)).toEqual([{ user: ["acc-1"] }]);
  });

  it("claims the site on a grant, creating P0's roles where they are missing", async () => {
    net.reply(`GET ${SITE_ROLES}`, {
      status: 200,
      body: [{ id: 10002, name: "Administrators" }],
    });
    net.reply(
      `POST ${SITE_ROLES}`,
      {
        status: 200,
        body: { id: 10299, name: "P0 agent: read", description: OURS },
      },
      {
        status: 200,
        body: { id: 10300, name: "P0 agent: write", description: OURS },
      }
    );

    await setPolicies([{ type: "space", roleId: "10200" }], ["10200"]);

    expect(net.posted(SITE_ROLES)).toEqual([
      { name: "P0 agent: read", description: OURS },
      { name: "P0 agent: write", description: OURS },
    ]);
    expect(jiraCalls()).toContain(`POST ${VIEWER}`);
  });

  it("refuses a grant when another organization manages the site's P0 roles, and changes nothing", async () => {
    net.reply(`GET ${SITE_ROLES}`, {
      status: 200,
      body: [
        { id: Number(READ_ID), name: "P0 agent: read", description: THEIRS },
      ],
    });

    await expect(
      setPolicies([{ type: "space", roleId: "10200" }], ["10200"])
    ).rejects.toMatchObject({ data: { type: "validation_error" } });
    expect(jiraCalls()).toEqual([`GET ${PROJECT_ROLES}`, `GET ${SITE_ROLES}`]);
  });

  it("removes the account from the recorded space role on revoke", async () => {
    await setPolicies([], ["10200"]);

    expect(jiraCalls()).toEqual([
      `GET ${PROJECT_ROLES}`,
      `DELETE ${VIEWER}?user=acc-1`,
    ]);
  });

  it("moves the account from one recorded space role to another", async () => {
    await setPolicies([{ type: "space", roleId: "10201" }], ["10200"]);

    expect(jiraCalls()).toEqual([
      `GET ${PROJECT_ROLES}`,
      `GET ${SITE_ROLES}`,
      `POST ${MEMBER}`,
      `DELETE ${VIEWER}?user=acc-1`,
    ]);
  });

  it("fails with object_not_found for a role the project no longer has, and changes nothing", async () => {
    await expect(
      setPolicies([{ type: "space", roleId: "10999" }], ["10999"])
    ).rejects.toMatchObject({
      data: { type: "object_not_found", payload: { roleId: "10999" } },
    });
    expect(jiraCalls()).toEqual([`GET ${PROJECT_ROLES}`, `GET ${SITE_ROLES}`]);
  });

  it("removes the account from a recorded role the project has since deleted", async () => {
    net.reply(`DELETE ${API}/project/ENG/role/10999?user=acc-1`, {
      status: 404,
    });
    replyAdmin(true);

    await setPolicies([], ["10999"]);

    expect(jiraCalls()).toEqual([
      `GET ${PROJECT_ROLES}`,
      `DELETE ${API}/project/ENG/role/10999?user=acc-1`,
      `GET ${PERMISSIONS}`,
    ]);
  });
});

describe("setPoliciesForUser, a deleted project", () => {
  it("succeeds when no policy remains and the project is gone", async () => {
    net.reply(`GET ${PROJECT_ROLES}`, { status: 404 });
    replyAdmin(true);

    await setPolicies([], ["10200"]);

    expect(jiraCalls()).toEqual([`GET ${PROJECT_ROLES}`, `GET ${PERMISSIONS}`]);
  });

  it("fails when the project seems gone but the admin account has lost Administer Jira", async () => {
    net.reply(`GET ${PROJECT_ROLES}`, { status: 404 });
    replyAdmin(false);

    await expect(setPolicies([])).rejects.toMatchObject({
      data: { type: "insufficient_privileges" },
    });
  });

  it("fails with object_not_found when it grants a role on a missing project", async () => {
    net.reply(`GET ${PROJECT_ROLES}`, { status: 404 });

    await expect(setPolicies([read])).rejects.toMatchObject({
      data: { type: "object_not_found" },
    });
  });
});

describe("setPoliciesForUser, rate limits", () => {
  const limited = { status: 429, headers: { "Retry-After": "6" } };

  it("shares one deadline across a grant's calls, and stops before adding the account", async () => {
    // Each call is rate limited once, so each one alone gets through.
    net.reply(`GET ${PROJECT_ROLES}`, limited, {
      status: 200,
      body: { "P0 agent: write": `${API}/project/10000/role/${WRITE_ID}` },
    });
    net.reply(`GET ${SITE_ROLES}`, limited, {
      status: 200,
      body: [
        { id: Number(READ_ID), name: "P0 agent: read", description: OURS },
        { id: Number(WRITE_ID), name: "P0 agent: write", description: OURS },
      ],
    });
    net.reply(`GET ${SCHEME}`, limited, { status: 200, body: { id: 10050 } });
    net.reply(`GET ${GRANTS}`, limited, {
      status: 200,
      body: { permissions: [] },
    });
    net.reply(`POST ${GRANTS}`, limited, { status: 201, body: { id: 2 } });

    const start = Date.now();
    const failure = await withoutWaits(() =>
      connectorErrorOf(setPolicies([write]))
    );

    // Four 6 s waits fit in the 30 s budget. A fifth doesn't.
    expect(failure.data.type).toBe("rate_limited");
    expect(failure.message).toContain(
      "Try the request again in a few minutes."
    );
    expect(Date.now() - start).toBeLessThanOrEqual(REQUEST_BUDGET_MS);
    expect(jiraCalls()).not.toContain(`POST ${WRITE}`);
  });
});

describe("deleteUser", () => {
  it("leaves the account alone", async () => {
    await caller().deleteUser({
      userId: "acc-1",
      userBody: { cloudId: CLOUD_ID, accountId: "acc-1" },
      context,
    });

    expect(net.fetch).not.toHaveBeenCalled();
  });
});
