import { describe, expect, it } from "vitest";

import { ACCOUNT_ID } from "../../../__tests__/fixtures.ts";
import type { Resource } from "../definition.ts";
import { toTokenPolicies, zoneNamesOf } from "../token-body.ts";

const ACCOUNT_KEY = `com.cloudflare.api.account.${ACCOUNT_ID}`;
const ZONE_IDS = new Map([["example.com", "zone-1"]]);

const policiesOf = (resources: Resource[]) =>
  toTokenPolicies(ACCOUNT_ID, resources, ZONE_IDS);

describe("toTokenPolicies", () => {
  it("grants account groups on the account", () => {
    expect(policiesOf([{ groups: ["a", "b"], scope: "account" }])).toEqual({
      missingZones: [],
      policies: [
        {
          effect: "allow",
          permission_groups: [{ id: "a" }, { id: "b" }],
          resources: { [ACCOUNT_KEY]: "*" },
        },
      ],
    });
  });

  it("grants all-zones groups on every zone, under the account", () => {
    expect(policiesOf([{ groups: ["z"], scope: "all-zones" }])).toEqual({
      missingZones: [],
      policies: [
        {
          effect: "allow",
          permission_groups: [{ id: "z" }],
          resources: {
            [ACCOUNT_KEY]: { "com.cloudflare.api.account.zone.*": "*" },
          },
        },
      ],
    });
  });

  it("grants zone groups on that zone by id, under the account", () => {
    expect(
      policiesOf([{ groups: ["z"], scope: "zone", zone: "example.com" }])
    ).toEqual({
      missingZones: [],
      policies: [
        {
          effect: "allow",
          permission_groups: [{ id: "z" }],
          resources: {
            [ACCOUNT_KEY]: { "com.cloudflare.api.zone.zone-1": "*" },
          },
        },
      ],
    });
  });

  it("makes one policy per resource, in order", () => {
    const { policies } = policiesOf([
      { groups: ["a"], scope: "account" },
      { groups: ["z"], scope: "zone", zone: "example.com" },
      { groups: ["y"], scope: "all-zones" },
    ]);

    expect(policies.map(({ permission_groups }) => permission_groups)).toEqual([
      [{ id: "a" }],
      [{ id: "z" }],
      [{ id: "y" }],
    ]);
  });

  it("leaves out a zone the account doesn't have, and names it", () => {
    expect(
      policiesOf([
        { groups: ["a"], scope: "account" },
        { groups: ["z"], scope: "zone", zone: "gone.example" },
      ])
    ).toEqual({
      missingZones: ["gone.example"],
      policies: [
        {
          effect: "allow",
          permission_groups: [{ id: "a" }],
          resources: { [ACCOUNT_KEY]: "*" },
        },
      ],
    });
  });
});

describe("zoneNamesOf", () => {
  it("names only the zones of zone resources", () => {
    expect(
      zoneNamesOf([
        { groups: ["a"], scope: "account" },
        { groups: ["y"], scope: "all-zones" },
        { groups: ["z"], scope: "zone", zone: "example.com" },
      ])
    ).toEqual(["example.com"]);
  });
});
