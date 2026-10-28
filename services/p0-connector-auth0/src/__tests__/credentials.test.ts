import { describe, expect, it } from "vitest";

import { tenant, tenantCredentials } from "../credentials.ts";
import { CREDENTIALS, GCP_SECRET } from "./fixtures.ts";

describe("tenant", () => {
  it.each([
    "acme.auth0.com",
    "a.auth0.com",
    "acme.us.auth0.com",
    "acme.eu.auth0.com",
    "acme-prod.au.auth0.com",
    "a1.jp.auth0.com",
    "dev-abc123xyz.ca.auth0.com",
  ])("takes the canonical domain %s", (domain) => {
    expect(tenant.parse(domain)).toBe(domain);
  });

  it.each([
    ["a custom domain", "login.acme.com"],
    ["another host under it", "acme.auth0.com.evil.com"],
    ["a scheme", "https://acme.auth0.com"],
    ["a path", "acme.auth0.com/api"],
    ["a port", "acme.auth0.com:443"],
    ["upper case", "Acme.auth0.com"],
    ["no tenant name", "auth0.com"],
    ["an empty name", ".auth0.com"],
    ["a leading hyphen", "-acme.auth0.com"],
    ["a trailing hyphen", "acme-.auth0.com"],
    ["a long region", "acme.usa.auth0.com"],
    ["a user part", "x@acme.auth0.com"],
    ["an underscore before the region", "acme_us.auth0.com"],
    ["whitespace", " acme.auth0.com"],
  ])("refuses %s", (_case, domain) => {
    expect(tenant.safeParse(domain).success).toBe(false);
  });
});

describe("tenantCredentials", () => {
  it("takes an AWS or a Google pointer", () => {
    expect(tenantCredentials.parse(CREDENTIALS)).toEqual(CREDENTIALS);
    const gcp = { ...CREDENTIALS, clientSecret: GCP_SECRET };
    expect(tenantCredentials.parse(gcp)).toEqual(gcp);
  });

  it.each([
    ["an empty client id", { clientId: "" }],
    ["a client id with a space", { clientId: "abc def" }],
    [
      "a pointer without its region",
      { clientSecret: { manager: "aws", secretId: "s" } },
    ],
    [
      "an unknown manager",
      { clientSecret: { manager: "vault", secretId: "s" } },
    ],
    ["an empty secret id", { clientSecret: { ...GCP_SECRET, secretId: "" } }],
  ])("refuses %s", (_case, change) => {
    expect(
      tenantCredentials.safeParse({ ...CREDENTIALS, ...change }).success
    ).toBe(false);
  });
});
