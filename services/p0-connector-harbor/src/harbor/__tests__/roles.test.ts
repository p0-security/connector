import { describe, expect, expectTypeOf, it } from "vitest";

import {
  connectorError,
  propertySeed,
  seededRandom,
} from "../../__tests__/fixtures.ts";
import {
  type HarborRole,
  harborRole,
} from "../../accesses/project-role/definition.ts";
import {
  ROLES_BY_RANK,
  knownRoleOf,
  rankOf,
  ranksBelow,
  roleId,
  roleOf,
} from "../roles.ts";

describe("the role map", () => {
  // Harbor's src/common/const.go.
  it.each<[HarborRole, number]>([
    ["projectAdmin", 1],
    ["developer", 2],
    ["guest", 3],
    ["maintainer", 4],
    ["limitedGuest", 5],
  ])("maps %s to Harbor's id %i, and back", (role, id) => {
    expect(roleId(role)).toBe(id);
    expect(roleOf(id)).toBe(role);
  });

  it("lists every role the schema takes, in its type", () => {
    expectTypeOf<(typeof ROLES_BY_RANK)[number]>().toEqualTypeOf<HarborRole>();
  });

  it("covers every role the schema takes, once", () => {
    expect([...ROLES_BY_RANK].sort()).toEqual([...harborRole.options].sort());
  });

  // Harbor's rolePower: each role holds every permission of the ones below.
  it("ranks the roles by what they hold, lowest first", () => {
    expect(ROLES_BY_RANK).toEqual([
      "limitedGuest",
      "guest",
      "developer",
      "maintainer",
      "projectAdmin",
    ]);
    expect(rankOf("projectAdmin")).toBeGreaterThan(rankOf("maintainer"));
    expect(rankOf("maintainer")).toBeGreaterThan(rankOf("developer"));
    expect(rankOf("developer")).toBeGreaterThan(rankOf("guest"));
    expect(rankOf("guest")).toBeGreaterThan(rankOf("limitedGuest"));
  });

  it("says which of two roles holds less", () => {
    expect(ranksBelow("developer", "maintainer")).toBe(true);
    expect(ranksBelow("maintainer", "developer")).toBe(false);
    expect(ranksBelow("guest", "guest")).toBe(false);
    // By id, projectAdmin (1) would come first.
    expect(ranksBelow("projectAdmin", "limitedGuest")).toBe(false);
  });

  describe("knownRoleOf", () => {
    const where = { host: "harbor.example.com", project: "team", userId: "42" };

    it("reads a row's role", () => {
      expect(knownRoleOf({ roleId: 4 }, where)).toBe("maintainer");
    });

    // Harbor stores any role id a PUT sends.
    it("refuses a role id that isn't one of Harbor's, naming it, with no reason", async () => {
      const { data } = await connectorError(async () =>
        knownRoleOf({ roleId: 9 }, where)
      );

      expect(data).toEqual({
        type: "validation_error",
        message:
          "Harbor user 42 holds role id 9 on project team on harbor.example.com, which isn't one of Harbor's project roles. Ask a Harbor admin to set the user's role on the project's Members tab.",
        payload: {
          host: "harbor.example.com",
          project: "team",
          userId: "42",
          roleId: 9,
        },
      });
    });
  });

  // The ids aren't in rank order, which is why nothing ranks by id.
  it("doesn't rank the roles the way their ids sort", () => {
    const byId = [...ROLES_BY_RANK].sort((a, b) => roleId(a) - roleId(b));
    expect(byId).not.toEqual([...ROLES_BY_RANK]);
  });

  const seed = propertySeed();
  it(
    `is a bijection between the five roles and ids 1 to 5, and knows no other id (PROPERTY_SEED=${seed})`,
    { timeout: 30_000 },
    () => {
      const random = seededRandom(seed);
      const IDS = [
        () => 1 + Math.floor(random() * 5),
        () => Math.floor(random() * 2e9) - 1e9,
        () => random() * 10,
        () => Number.NaN,
        () => 0,
        () => 6,
      ];
      for (let i = 0; i < 2000; i++) {
        const make = IDS[Math.floor(random() * IDS.length)];
        if (make === undefined) throw new Error("picked from no ids");
        const id = make();
        const role = roleOf(id);
        const known = Number.isInteger(id) && id >= 1 && id <= 5;
        if (known !== (role !== undefined)) {
          throw new Error(`roleOf(${id}) is ${String(role)}`);
        }
        if (role !== undefined && roleId(role) !== id) {
          throw new Error(`roleId(roleOf(${id})) is ${roleId(role)}`);
        }
      }
      // Rank is a strict total order on the five.
      expect(new Set(ROLES_BY_RANK.map(rankOf)).size).toBe(5);
    }
  );
});
