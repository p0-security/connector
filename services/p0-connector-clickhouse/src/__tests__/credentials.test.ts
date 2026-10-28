import { describe, expect, it } from "vitest";

import { organizationCredentials, organizationId } from "../credentials.ts";
import { CREDENTIALS, GCP_SECRET, ORGANIZATION_ID } from "./fixtures.ts";

describe("organizationId", () => {
  it.each([
    ORGANIZATION_ID,
    ORGANIZATION_ID.toUpperCase(),
    "123e4567-e89b-42d3-a456-426614174000",
  ])("takes the UUID %s", (id) => {
    expect(organizationId.parse(id)).toBe(id);
  });

  it.each([
    ["the all-zero ID", "00000000-0000-0000-0000-000000000000"],
    ["no dashes", ORGANIZATION_ID.replace(/-/g, "")],
    ["a path", `${ORGANIZATION_ID}/services`],
    ["a dot segment", ".."],
    ["whitespace", ` ${ORGANIZATION_ID}`],
    ["a version-0 UUID", "123e4567-e89b-02d3-a456-426614174000"],
    ["an empty string", ""],
  ])("refuses %s", (_case, id) => {
    expect(organizationId.safeParse(id).success).toBe(false);
  });
});

describe("organizationCredentials", () => {
  it("takes an AWS or a Google pointer", () => {
    expect(organizationCredentials.parse(CREDENTIALS)).toEqual(CREDENTIALS);
    const gcp = { ...CREDENTIALS, apiKeySecret: GCP_SECRET };
    expect(organizationCredentials.parse(gcp)).toEqual(gcp);
  });

  it.each([
    [
      "a pointer without its region",
      { apiKeySecret: { manager: "aws", secretId: "s" } },
    ],
    [
      "an unknown manager",
      { apiKeySecret: { manager: "vault", secretId: "s" } },
    ],
    ["an empty secret ID", { apiKeySecret: { ...GCP_SECRET, secretId: "" } }],
    ["the key itself for the pointer", { apiKeySecret: "a-key-secret" }],
    ["no organization", { organizationId: undefined }],
  ])("refuses %s", (_case, change) => {
    expect(
      organizationCredentials.safeParse({ ...CREDENTIALS, ...change }).success
    ).toBe(false);
  });
});
