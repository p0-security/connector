import { describe, expect, it } from "vitest";

import {
  P0_ROLES,
  accountQuery,
  projectQuery,
  roleSpec,
  site,
  siteQuery,
  tokenSpec,
} from "../connector.ts";

const SITE = {
  cloudId: "0e5a4f1e-2b7c-4c8d-9f10-3a4b5c6d7e8f",
  adminClientId: "admin-client",
  adminSecret: {
    manager: "gcp",
    projectId: "acme-vault",
    secretId: "jira-admin",
  },
  tenantId: "acme",
};

const ROLE_CONTEXT = {
  requestId: "r-1",
  site: SITE,
  projectKey: "ENG",
  roleIds: ["10200"],
};

const TOKEN_CONTEXT = {
  requestId: "r-1",
  site: SITE,
  vault: { projectId: "acme-vault" },
  poolSecret: {
    manager: "gcp",
    projectId: "acme-vault",
    secretId: "jira-pool-1",
  },
};

describe("site", () => {
  it("parses a site with a GCP secret", () => {
    expect(site.parse(SITE)).toEqual(SITE);
  });

  it.each(["not-a-uuid", "../../evil", "0e5a4f1e2b7c4c8d9f103a4b5c6d7e8f"])(
    "refuses the cloud id %s",
    (cloudId) => {
      expect(() => site.parse({ ...SITE, cloudId })).toThrow();
    }
  );

  it.each(["aws", "azure"])("refuses a %s secret", (manager) => {
    expect(() =>
      site.parse({
        ...SITE,
        adminSecret: { ...SITE.adminSecret, manager, region: "us-east-1" },
      })
    ).toThrow();
  });

  it("refuses a secret's full resource name", () => {
    expect(() =>
      site.parse({
        ...SITE,
        adminSecret: {
          ...SITE.adminSecret,
          secretId: "projects/other/secrets/jira-admin",
        },
      })
    ).toThrow();
  });

  it("requires the P0 tenant id", () => {
    const { tenantId: _, ...withoutTenant } = SITE;
    expect(() => site.parse(withoutTenant)).toThrow();
  });

  it.each(["", "acme corp", "acme/other", "a".repeat(129)])(
    "refuses the tenant id %j",
    (tenantId) => {
      expect(() => site.parse({ ...SITE, tenantId })).toThrow();
    }
  );

  it("accepts a tenant id of letters, digits, hyphens and underscores", () => {
    expect(site.parse({ ...SITE, tenantId: "Acme_prod-2" }).tenantId).toBe(
      "Acme_prod-2"
    );
  });
});

describe("project keys", () => {
  it.each(["ENG", "AB1", "A_B"])("accepts %s", (projectKey) => {
    expect(projectQuery.parse({ site: SITE, projectKey }).projectKey).toBe(
      projectKey
    );
  });

  it.each(["eng", "E", "1AB", "ENG/../X", "ENG?x=1", ""])(
    "refuses %s",
    (projectKey) => {
      expect(() => projectQuery.parse({ site: SITE, projectKey })).toThrow();
      expect(() =>
        roleSpec.requestContext({ ...ROLE_CONTEXT, projectKey })
      ).toThrow();
    }
  );
});

describe("install queries", () => {
  it("takes a site", () => {
    expect(siteQuery.parse({ site: SITE })).toEqual({ site: SITE });
  });

  it("takes a site and an email", () => {
    expect(accountQuery.parse({ site: SITE, email: "a@acme.com" })).toEqual({
      site: SITE,
      email: "a@acme.com",
    });
  });
});

describe("role", () => {
  it("takes the site's cloud id beside the account id", () => {
    const body = { cloudId: SITE.cloudId, accountId: "712020:abc-123" };
    expect(roleSpec.userBody(body)).toEqual(body);
    expect(roleSpec.userId("712020:abc-123")).toBe("712020:abc-123");
  });

  it.each([
    { type: "p0", level: "read" },
    { type: "p0", level: "write" },
    { type: "space", roleId: "10200" },
  ])("accepts the policy %o", (policy) => {
    expect(roleSpec.policy(policy)).toEqual(policy);
  });

  it.each([
    { type: "p0", level: "admin" },
    { type: "space", roleId: "Viewer" },
    { type: "space" },
    { role: "read" },
  ])("refuses the policy %o", (policy) => {
    expect(() => roleSpec.policy(policy)).toThrow();
  });

  it("parses its request context, with or without recorded role ids", () => {
    expect(roleSpec.requestContext(ROLE_CONTEXT)).toEqual(ROLE_CONTEXT);
    expect(roleSpec.requestContext({ ...ROLE_CONTEXT, roleIds: [] })).toEqual({
      ...ROLE_CONTEXT,
      roleIds: [],
    });
    expect(() =>
      roleSpec.requestContext({ ...ROLE_CONTEXT, roleIds: ["../10200"] })
    ).toThrow();
  });

  it("names P0's two roles and their permissions", () => {
    expect(P0_ROLES.read).toEqual({
      name: "P0 agent: read",
      permissions: ["BROWSE_PROJECTS"],
    });
    expect(P0_ROLES.write.name).toBe("P0 agent: write");
    expect(P0_ROLES.write.permissions).toEqual([
      "BROWSE_PROJECTS",
      "ADD_COMMENTS",
      "CREATE_ISSUES",
      "EDIT_ISSUES",
      "TRANSITION_ISSUES",
      "EDIT_OWN_COMMENTS",
      "WORK_ON_ISSUES",
      "EDIT_OWN_WORKLOGS",
      "LINK_ISSUES",
      "CREATE_ATTACHMENTS",
      "ASSIGN_ISSUES",
      "SCHEDULE_ISSUES",
      "RESOLVE_ISSUES",
    ]);
  });
});

describe("token", () => {
  it("names the request's secret by its bare name", () => {
    expect(tokenSpec.userBody("p0-jira-ai-r-1")).toBe("p0-jira-ai-r-1");
    expect(() =>
      tokenSpec.userId("projects/p/secrets/p0-jira-ai-r-1")
    ).toThrow();
  });

  it("parses its request context and refuses a non-GCP pool secret", () => {
    expect(tokenSpec.requestContext(TOKEN_CONTEXT)).toEqual(TOKEN_CONTEXT);
    expect(() =>
      tokenSpec.requestContext({
        ...TOKEN_CONTEXT,
        poolSecret: { manager: "aws", region: "us-east-1", secretId: "x" },
      })
    ).toThrow();
  });

  it("takes the leased pool account as its policy", () => {
    expect(tokenSpec.policy({ accountId: "abc" })).toEqual({
      accountId: "abc",
    });
  });
});
