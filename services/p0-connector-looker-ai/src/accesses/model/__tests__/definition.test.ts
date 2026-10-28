import { describe, expect, it } from "vitest";

import { schema } from "../definition.ts";

const secrets = {
  manager: "gcp",
  adminKeySecretId: "p0_install_looker_acme_admin-key",
  projectId: "acme-prod",
};

const context = (overrides: Record<string, unknown> = {}) => ({
  requestId: "r-1",
  baseUrl: "https://example.looker.app",
  secrets,
  ...overrides,
});

describe("the instance URL", () => {
  const accepts = (baseUrl: string) =>
    schema.requestContext.safeParse(context({ baseUrl })).success;

  it.each([
    "https://example.looker.app",
    "https://1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d.looker.app",
    "https://example.us-central1.looker.app",
  ])("accepts %s", (baseUrl) => {
    expect(accepts(baseUrl)).toBe(true);
  });

  // The connector sends the Admin key to this host.
  it.each([
    ["another host", "https://example.com"],
    [
      "a host that only starts like Looker's",
      "https://example.looker.app.evil.com",
    ],
    ["a host that only ends like Looker's", "https://evil-looker.app"],
    ["the bare domain", "https://looker.app"],
    ["plain HTTP", "http://example.looker.app"],
    ["Looker's host as the user name", "https://example.looker.app@evil.com"],
    ["Looker's host in the fragment", "https://evil.com#@example.looker.app"],
    ["a user name", "https://admin@example.looker.app"],
    ["a port", "https://example.looker.app:8443"],
    ["a path", "https://example.looker.app/api/4.0"],
    ["a trailing slash", "https://example.looker.app/"],
    ["a query", "https://evil.com?.looker.app"],
    ["an upper-case host", "https://EXAMPLE.looker.app"],
    ["a line break", "https://example.looker.app\n"],
  ])("refuses %s", (_, baseUrl) => {
    expect(accepts(baseUrl)).toBe(false);
  });
});

describe("the content folder", () => {
  const accepts = (contentFolderId?: string) =>
    schema.requestContext.safeParse(context({ contentFolderId })).success;

  it.each(["123", "lookml"])("accepts the folder id %s", (id) => {
    expect(accepts(id)).toBe(true);
  });

  it("is optional", () => {
    expect(accepts(undefined)).toBe(true);
  });

  // The id goes into a URL path.
  it.each([
    ["a dot segment", ".."],
    ["a slash", "1/../2"],
    ["a query", "1?x=y"],
    ["nothing", ""],
  ])("refuses %s", (_, id) => {
    expect(accepts(id)).toBe(false);
  });
});

describe("the Admin key's location", () => {
  it("is in Google Secret Manager", () => {
    expect(schema.requestContext.safeParse(context()).success).toBe(true);
    expect(
      schema.requestContext.safeParse(
        context({
          secrets: {
            manager: "aws",
            adminKeySecretId: "p0/install/looker/acme/admin-key",
            region: "us-west-2",
          },
        })
      ).success
    ).toBe(false);
  });
});

describe("the user", () => {
  it.each(["p0_access-token_looker_acme_1a2b3c4d", "a", "A".repeat(255)])(
    "accepts the secret id %s",
    (name) => {
      expect(schema.userBody.safeParse(name).success).toBe(true);
      expect(schema.userId.safeParse(name).success).toBe(true);
    }
  );

  // A full resource name would let a request name a secret in another project.
  it.each([
    ["a secret's resource name", "projects/other/secrets/p0_grant"],
    ["a canonical P0 name", "p0/access-token/looker/acme/1a2b3c4d"],
    ["a dot", "p0_grant.pem"],
    ["a space", "p0 grant"],
    ["nothing", ""],
    ["256 characters", "a".repeat(256)],
  ])("refuses %s", (_, name) => {
    expect(schema.userBody.safeParse(name).success).toBe(false);
    expect(schema.userId.safeParse(name).success).toBe(false);
  });
});

describe("the policy", () => {
  it.each(["read", "edit"])("accepts a model at the %s level", (level) => {
    expect(schema.policy.parse({ model: "thelook", level })).toEqual({
      model: "thelook",
      level,
    });
  });

  it("accepts null, for no access", () => {
    expect(schema.policy.parse(null)).toBeNull();
  });

  it.each([
    ["the develop level", { model: "thelook", level: "develop" }],
    ["no level", { model: "thelook" }],
    ["no model", { model: "", level: "read" }],
  ])("refuses %s", (_, policy) => {
    expect(schema.policy.safeParse(policy).success).toBe(false);
  });
});

describe("the model listing", () => {
  it("takes the instance, and no request", () => {
    expect(
      schema.listerQuery.parse({
        type: "model",
        context: { baseUrl: "https://example.looker.app", secrets },
      })
    ).toEqual({
      type: "model",
      context: { baseUrl: "https://example.looker.app", secrets },
    });
  });
});
