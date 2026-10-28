import { describe, expect, it, vi } from "vitest";

import {
  ACCOUNT,
  EMAIL,
  LAUNCHDARKLY_HOST,
  MEMBER,
  MEMBER_ID,
  ROLE_ID,
  USER_BODY,
  connectorError,
  logger,
  noPause,
  stubPatternAndToken,
  writes,
} from "../../../__tests__/fixtures.ts";
import {
  type FakeMember,
  errorAnswer,
  fakeMember,
  newFakeLaunchDarkly,
} from "../../../launchdarkly/__tests__/fake-launchdarkly.ts";
import { BASE_ROLES_BY_RANK } from "../../../launchdarkly/roles.ts";
import type { BaseRole, PriorBaseRole } from "../definition.ts";
import { newBaseRolePrimitives } from "../handler.ts";

// The secret manager is `secrets.test.ts`'s business.
vi.mock("../../../secrets.ts");

const launchDarklyWith = (member: Partial<FakeMember> = {}) =>
  newFakeLaunchDarkly({
    members: [fakeMember({ _id: MEMBER_ID, email: EMAIL, ...member })],
  });

type LaunchDarkly = ReturnType<typeof launchDarklyWith>;

const roleOf = (launchDarkly: LaunchDarkly) =>
  launchDarkly.state.members?.[0]?.role;

/**
 * Sets the member's base role for a request for `role`. A grant holds the
 * request's role in `policies`, the siblings' alongside it. A revoke holds
 * only the siblings'.
 */
const setRole = (
  role: BaseRole,
  options: {
    operation?: "grant" | "revoke";
    priorRole?: PriorBaseRole;
    siblings?: BaseRole[];
    policies?: BaseRole[];
  } = {}
) => {
  const {
    operation = "grant",
    priorRole = "reader",
    siblings = [],
    policies,
  } = options;
  return newBaseRolePrimitives(logger, noPause).setPoliciesForUser(
    {
      ...ACCOUNT,
      requestId: "req-1",
      email: EMAIL,
      operation,
      role,
      priorRole,
    },
    MEMBER_ID,
    USER_BODY,
    policies ?? (operation === "grant" ? [role, ...siblings] : siblings)
  );
};

const grant = (role: BaseRole, siblings: BaseRole[] = []) =>
  setRole(role, { siblings });

const revoke = (
  role: BaseRole,
  priorRole: PriorBaseRole,
  siblings: BaseRole[] = []
) => setRole(role, { operation: "revoke", priorRole, siblings });

stubPatternAndToken();

describe("a grant", () => {
  it("raises a lower base role, pinning the role it read", async () => {
    const launchDarkly = launchDarklyWith({ role: "reader" });

    await grant("writer");

    expect(roleOf(launchDarkly)).toBe("writer");
    expect(writes(launchDarkly)).toEqual([
      {
        call: `PATCH ${MEMBER}`,
        body: [
          { op: "test", path: "/role", value: "reader" },
          { op: "replace", path: "/role", value: "writer" },
        ],
      },
    ]);
  });

  // The sibling for Admin is STAGED: it may leave STAGED without a connector
  // call, and then nothing would lower the member from Admin.
  it("raises to the request's own role only, not to a sibling's in the policies", async () => {
    const launchDarkly = launchDarklyWith({ role: "reader" });

    await grant("writer", ["admin"]);

    expect(roleOf(launchDarkly)).toBe("writer");
    expect(writes(launchDarkly)).toEqual([
      {
        call: `PATCH ${MEMBER}`,
        body: [
          { op: "test", path: "/role", value: "reader" },
          { op: "replace", path: "/role", value: "writer" },
        ],
      },
    ]);

    // The staged Admin leaves without a call: Writer's revoke lowers to the
    // prior role.
    await revoke("writer", "reader");
    expect(roleOf(launchDarkly)).toBe("reader");
  });

  it.each<[current: string, role: BaseRole]>([
    ["writer", "writer"],
    ["admin", "writer"],
    ["writer", "reader"],
    ["owner", "admin"],
  ])(
    "leaves a %s alone when granting %s: it never lowers",
    async (current, role) => {
      const launchDarkly = launchDarklyWith({ role: current });

      await grant(role);

      expect(roleOf(launchDarkly)).toBe(current);
      expect(writes(launchDarkly)).toEqual([]);
    }
  );

  // LaunchDarkly ignores the base role of a member with a custom role.
  it("refuses a member with custom roles (base_role_ignored)", async () => {
    const launchDarkly = launchDarklyWith({
      role: "reader",
      customRoles: [ROLE_ID],
    });

    const { data } = await connectorError(() => grant("writer"));

    expect(data).toMatchObject({
      type: "validation_error",
      payload: {
        host: LAUNCHDARKLY_HOST,
        memberId: MEMBER_ID,
        reason: "base_role_ignored",
      },
    });
    expect(writes(launchDarkly)).toEqual([]);
  });

  it("refuses a base role outside the rank, which it can't compare", async () => {
    const launchDarkly = launchDarklyWith({ role: "archived" });

    const { data } = await connectorError(() => grant("writer"));

    expect(data).toMatchObject({
      type: "validation_error",
      payload: {
        host: LAUNCHDARKLY_HOST,
        memberId: MEMBER_ID,
        role: "archived",
      },
    });
    expect(writes(launchDarkly)).toEqual([]);
  });

  // Someone made the member an owner between the read and the write.
  it("fails, writing over nothing, when the role changed after it read it", async () => {
    const launchDarkly = launchDarklyWith({ role: "reader" });
    launchDarkly.intercept(({ method }) => {
      const member = launchDarkly.state.members?.[0];
      if (method === "PATCH" && member) member.role = "owner";
      return undefined;
    });

    const { data } = await connectorError(() => grant("writer"));

    expect(data).toMatchObject({
      type: "validation_error",
      payload: { status: 409 },
    });
    expect(roleOf(launchDarkly)).toBe("owner");
  });
});

describe("a revoke", () => {
  it("lowers to the prior role when no sibling holds a role", async () => {
    const launchDarkly = launchDarklyWith({ role: "writer" });

    await revoke("writer", "reader");

    expect(roleOf(launchDarkly)).toBe("reader");
    expect(writes(launchDarkly)).toEqual([
      {
        call: `PATCH ${MEMBER}`,
        body: [
          { op: "test", path: "/role", value: "writer" },
          { op: "replace", path: "/role", value: "reader" },
        ],
      },
    ]);
  });

  it("lowers to no_access when the member held none", async () => {
    const launchDarkly = launchDarklyWith({ role: "writer" });

    await revoke("writer", "no_access");

    expect(roleOf(launchDarkly)).toBe("no_access");
  });

  it("lowers to the highest role a sibling still holds", async () => {
    const launchDarkly = launchDarklyWith({ role: "admin" });

    await revoke("admin", "reader", ["writer"]);

    expect(roleOf(launchDarkly)).toBe("writer");
  });

  it.each<[current: string, priorRole: PriorBaseRole, siblings: BaseRole[]]>([
    // Someone lowered the member outside P0.
    ["reader", "writer", []],
    // A sibling for Admin is approved, and its grant hasn't run yet.
    ["writer", "reader", ["admin"]],
    ["writer", "reader", ["writer"]],
  ])(
    "leaves a %s alone with prior role %s and siblings %j: it never raises",
    async (current, priorRole, siblings) => {
      const launchDarkly = launchDarklyWith({ role: current });

      await revoke("writer", priorRole, siblings);

      expect(roleOf(launchDarkly)).toBe(current);
      expect(writes(launchDarkly)).toEqual([]);
    }
  );

  it("never writes over an owner", async () => {
    const launchDarkly = launchDarklyWith({ role: "owner" });

    await revoke("admin", "reader");

    expect(roleOf(launchDarkly)).toBe("owner");
    expect(writes(launchDarkly)).toEqual([]);
  });

  it("fails, changing nothing, on a base role outside the rank", async () => {
    const launchDarkly = launchDarklyWith({ role: "archived" });

    const { data } = await connectorError(() => revoke("writer", "reader"));

    expect(data).toMatchObject({
      type: "dependency_violation",
      payload: {
        host: LAUNCHDARKLY_HOST,
        memberId: MEMBER_ID,
        role: "archived",
      },
    });
    expect(writes(launchDarkly)).toEqual([]);
  });

  it("passes on LaunchDarkly's refusal of the write", async () => {
    const launchDarkly = launchDarklyWith({ role: "writer" });
    launchDarkly.intercept(({ method }) =>
      method === "PATCH"
        ? errorAnswer(403, { code: "forbidden", message: "Forbidden" })
        : undefined
    );

    const { data } = await connectorError(() => revoke("writer", "reader"));

    expect(data.type).toBe("insufficient_privileges");
    expect(roleOf(launchDarkly)).toBe("writer");
  });
});

// Writer and Admin both live for one member, from a Reader.
describe("overlapping requests", () => {
  it("revokes Writer, then Admin: Admin stays until its own revoke", async () => {
    const launchDarkly = launchDarklyWith({ role: "reader" });
    await grant("writer");
    await grant("admin", ["writer"]);
    expect(roleOf(launchDarkly)).toBe("admin");

    await revoke("writer", "reader", ["admin"]);
    expect(roleOf(launchDarkly)).toBe("admin");

    await revoke("admin", "reader");
    expect(roleOf(launchDarkly)).toBe("reader");
  });

  it("revokes Admin, then Writer: lowers to Writer, then to the prior role", async () => {
    const launchDarkly = launchDarklyWith({ role: "reader" });
    await grant("writer");
    await grant("admin", ["writer"]);

    await revoke("admin", "reader", ["writer"]);
    expect(roleOf(launchDarkly)).toBe("writer");

    await revoke("writer", "reader");
    expect(roleOf(launchDarkly)).toBe("reader");
  });

  // Admin's request is STAGED: approved, with its grant still to run.
  it("revokes Writer while Admin is staged but not granted, without raising", async () => {
    const launchDarkly = launchDarklyWith({ role: "reader" });
    await grant("writer");

    await revoke("writer", "reader", ["admin"]);
    expect(roleOf(launchDarkly)).toBe("writer");
    expect(writes(launchDarkly)).toHaveLength(1);

    await grant("admin");
    expect(roleOf(launchDarkly)).toBe("admin");
    await revoke("admin", "reader");
    expect(roleOf(launchDarkly)).toBe("reader");
  });

  // Admin's grant raised the member, and then failed: its rollback says
  // `grant` and holds only Writer.
  it("lowers back to Writer when Admin's grant fails after its write", async () => {
    const launchDarkly = launchDarklyWith({ role: "reader" });
    await grant("writer", ["admin"]);
    expect(roleOf(launchDarkly)).toBe("writer");
    await grant("admin", ["writer"]);
    expect(roleOf(launchDarkly)).toBe("admin");

    await setRole("admin", { operation: "grant", policies: ["writer"] });
    expect(roleOf(launchDarkly)).toBe("writer");

    await revoke("writer", "reader");
    expect(roleOf(launchDarkly)).toBe("reader");
  });
});

// Every combination of the member's base role now, the prior role, the
// request's role and its siblings', as a grant, a revoke, and a grant's
// rollback (a call that says grant without the request's own role):
// 5 x 4 x 3 x 8 x 3 = 1440.
describe("over every combination of roles", () => {
  const GRANTED: readonly BaseRole[] = ["reader", "writer", "admin"];
  const PRIOR: readonly PriorBaseRole[] = ["no_access", ...GRANTED];
  const SIBLINGS: readonly BaseRole[][] = [
    [],
    ["reader"],
    ["writer"],
    ["admin"],
    ["reader", "writer"],
    ["reader", "admin"],
    ["writer", "admin"],
    ["reader", "writer", "admin"],
  ];
  const KINDS = ["grant", "revoke", "rollback"] as const;
  const COMBINATIONS = BASE_ROLES_BY_RANK.flatMap((current) =>
    PRIOR.flatMap((priorRole) =>
      GRANTED.flatMap((role) =>
        SIBLINGS.flatMap((siblings) =>
          KINDS.map((kind) => ({ current, kind, priorRole, role, siblings }))
        )
      )
    )
  );

  const rank = (role: string) =>
    BASE_ROLES_BY_RANK.findIndex((ranked) => ranked === role);

  const highest = (roles: readonly string[]) =>
    roles.reduce<string | undefined>(
      (top, role) => (top === undefined || rank(role) > rank(top) ? role : top),
      undefined
    );

  /** The role the member must hold afterwards. */
  const expectedFor = (combination: {
    current: string;
    role: BaseRole;
    policies: BaseRole[];
    priorRole: PriorBaseRole;
    revokes: boolean;
  }): string => {
    const { current, role, policies, priorRole, revokes } = combination;
    if (current === "owner") return "owner";
    // A grant raises to the request's own role only.
    if (!revokes) return rank(role) > rank(current) ? role : current;
    const goal = highest(policies) ?? priorRole;
    return rank(goal) < rank(current) ? goal : current;
  };

  it(
    "a grant leaves the higher role, a revoke the lower, and owner is never written over",
    { timeout: 60_000 },
    async () => {
      expect(COMBINATIONS).toHaveLength(1440);
      for (const { current, kind, priorRole, role, siblings } of COMBINATIONS) {
        const launchDarkly = launchDarklyWith({ role: current });
        const policies =
          kind === "grant"
            ? [role, ...siblings]
            : kind === "revoke"
              ? siblings
              : siblings.filter((sibling) => sibling !== role);
        // A rollback leaves the request's own role out of policies.
        const revokes = kind !== "grant";

        await setRole(role, {
          operation: kind === "revoke" ? "revoke" : "grant",
          priorRole,
          policies,
        });

        const got = roleOf(launchDarkly);
        const expected = expectedFor({
          current,
          policies,
          priorRole,
          revokes,
          role,
        });
        if (got !== expected) {
          throw new Error(
            `expected ${expected}, got ${got} for ${JSON.stringify({ current, priorRole, role, siblings, kind })}`
          );
        }
        vi.unstubAllGlobals();
      }
    }
  );
});
