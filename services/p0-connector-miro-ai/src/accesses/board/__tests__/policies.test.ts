import { describe, expect, it, vi } from "vitest";

import {
  AWS_SECRET,
  NEVER_SHOWN,
  TEAM_ID,
  USER_ID,
  connectorError,
  logger,
  recordLogger,
  stubToken,
} from "../../../__tests__/fixtures.ts";
import {
  type FakeFailure,
  type FakeMiroState,
  type FakeUser,
  newFakeMiro,
} from "../../../miro/__tests__/fake-miro.ts";
import { BOARD_ROLES_BY_RANK } from "../../../miro/roles.ts";
import { connectorRouter } from "../../../router.ts";
import type { BoardRole, PriorRole } from "../definition.ts";
import { newBoardPrimitives } from "../handler.ts";
import { REVOKE_ATTEMPTS } from "../policies.ts";

// The secret manager is `secrets.test.ts`'s business.
vi.mock("../../../secrets.ts");

const BOARD_ID = "uXjVOakxTk0=";
const MEMBER_ID = "3458764688981436603";
const EMAIL = "requester@example.com";
const USER_BODY = { boardId: BOARD_ID, memberId: MEMBER_ID, teamId: TEAM_ID };
const MEMBER_PATH = `/v2/boards/${BOARD_ID}/members/${MEMBER_ID}`;
const MEMBERS_PATH = `/v2/boards/${BOARD_ID}/members`;

const GRANTED: BoardRole[] = ["viewer", "commenter", "editor"];
const PRIOR: PriorRole[] = ["none", ...BOARD_ROLES_BY_RANK];

/**
 * A team with the requester in it, and the board with the connector user
 * as co-owner and the requester at `prior`, unless overridden. Ids go out
 * as JSON numbers, as Miro sends some, so a rounded read shows.
 */
const miroWith = ({
  prior = "none",
  connectorRole = "coowner",
  requester = {},
  ...overrides
}: {
  prior?: string;
  connectorRole?: string;
  requester?: Partial<FakeUser>;
} & FakeMiroState = {}) =>
  newFakeMiro({
    boardMembers: {
      [BOARD_ID]: [
        { id: USER_ID, role: connectorRole },
        ...(prior === "none" ? [] : [{ id: MEMBER_ID, role: prior }]),
      ],
    },
    numericIds: true,
    teamMemberIds: [USER_ID, MEMBER_ID],
    users: [
      { email: "connector@example.com", id: USER_ID },
      { email: EMAIL, id: MEMBER_ID, ...requester },
    ],
    ...overrides,
  });

type Miro = ReturnType<typeof miroWith>;

/** The requester's role on the board now, `none` when they aren't on it. */
const roleOf = (miro: Miro) =>
  miro.state.boardMembers?.[BOARD_ID]?.find(({ id }) => id === MEMBER_ID)
    ?.role ?? "none";

/**
 * Sets the requester's role for a request for `role`. A grant holds the
 * request's role in `policies`, the siblings' alongside it. A revoke holds
 * only the siblings'.
 */
const setRole = (
  role: BoardRole,
  options: {
    operation?: "grant" | "revoke";
    priorRole?: PriorRole;
    siblings?: BoardRole[];
    policies?: BoardRole[];
  } = {}
) => {
  const {
    operation = "grant",
    priorRole = "none",
    siblings = [],
    policies,
  } = options;
  return newBoardPrimitives(logger, async () => {}).setPoliciesForUser(
    {
      boardId: BOARD_ID,
      email: EMAIL,
      operation,
      priorRole,
      requestId: "req-1",
      role,
      secret: AWS_SECRET,
      teamId: TEAM_ID,
    },
    MEMBER_ID,
    USER_BODY,
    policies ?? (operation === "grant" ? [role, ...siblings] : siblings)
  );
};

const grant = (role: BoardRole, siblings: BoardRole[] = []) =>
  setRole(role, { siblings });

const revoke = (
  role: BoardRole,
  priorRole: PriorRole,
  siblings: BoardRole[] = []
) => setRole(role, { operation: "revoke", priorRole, siblings });

const rank = (role: string) => PRIOR.indexOf(role as PriorRole);

stubToken();

describe("a grant", () => {
  describe.each(PRIOR)("from %s", (prior) => {
    it.each(GRANTED)(
      "to %s raises the role, and never lowers it",
      async (goal) => {
        const miro = miroWith({ prior });

        await grant(goal);

        const raises = rank(goal) > rank(prior);
        expect(roleOf(miro)).toBe(raises ? goal : prior);
        const writes = miro.writes();
        if (!raises) {
          expect(writes).toEqual([]);
        } else if (prior !== "none") {
          expect(writes).toEqual([
            { body: { role: goal }, method: "PATCH", path: MEMBER_PATH },
          ]);
        } else if (goal === "viewer") {
          // Miro refuses a POST at viewer, so the member is added as a
          // commenter and lowered.
          expect(writes).toEqual([
            {
              body: { emails: [EMAIL], role: "commenter" },
              method: "POST",
              path: MEMBERS_PATH,
            },
            { body: { role: "viewer" }, method: "PATCH", path: MEMBER_PATH },
          ]);
        } else {
          expect(writes).toEqual([
            {
              body: { emails: [EMAIL], role: goal },
              method: "POST",
              path: MEMBERS_PATH,
            },
          ]);
        }
      }
    );
  });

  it("leaves a sibling's higher role in place", async () => {
    const miro = miroWith({ prior: "editor" });

    await grant("commenter", ["editor"]);

    expect(roleOf(miro)).toBe("editor");
    expect(miro.writes()).toEqual([]);
  });

  it("removes a new viewer again when lowering them from commenter fails", async () => {
    const miro = miroWith({
      failures: [{ method: "PATCH", path: /\/members\//, status: 500 }],
    });

    const error = await connectorError(() => grant("viewer"));

    expect(error.data.type).toBe("upstream_unavailable");
    expect(roleOf(miro)).toBe("none");
    expect(miro.writes().map(({ method }) => method)).toEqual([
      "POST",
      "PATCH",
      "DELETE",
    ]);
  });

  it("says so when removing the new viewer fails too", async () => {
    const failures: FakeFailure[] = [
      { method: "PATCH", path: /\/members\//, status: 500 },
      { method: "DELETE", path: /\/members\//, status: 500 },
    ];
    miroWith({ failures });

    const error = await connectorError(() => grant("viewer"));

    expect(error.data).toMatchObject({
      payload: { boardId: BOARD_ID, memberId: MEMBER_ID },
      type: "dependency_violation",
    });
    expect(error.message).toContain("Ask a Miro admin to remove them");
  });

  // Each refusal comes before any write, as a `validation_error` P0 shows.
  describe("refuses, before any write,", () => {
    it.each([
      [
        "a requester outside the team",
        { teamMemberIds: [USER_ID] },
        "not_in_team",
        "Your Miro user isn't in team Dev team. Ask a Miro admin to add you, then request again.",
      ],
      [
        "a requester whose team invite is pending",
        { requester: { state: "not_registered" as const } },
        "pending_invite",
        "You have a pending invite to Miro team Dev team. Accept it and create your Miro account, then request again.",
      ],
      [
        "a member whose email is no longer the requester's",
        { requester: { email: "someone-else@example.com" } },
        "member_changed",
        "Your Miro account changed after you requested access. Request access again.",
      ],
      [
        "a board the connector user can't share",
        { connectorRole: "editor" },
        "board_not_shareable",
        `P0 can't share board ${BOARD_ID}: its connector user must be the board's owner or co-owner.`,
      ],
      [
        "a token that belongs to another team",
        { teamId: "3458764688600000999" },
        "member_changed",
        `The Miro connector's access token belongs to another team than team ${TEAM_ID}. Check the token in the team's secret, then request access again.`,
      ],
    ])("%s", async (_, overrides, reason, message) => {
      const miro = miroWith(overrides);

      const error = await connectorError(() => grant("editor"));

      expect(error.data).toMatchObject({
        payload: { reason },
        type: "validation_error",
      });
      expect(error.message).toBe(message);
      expect(miro.writes()).toEqual([]);
    });

    it("a member Miro no longer has", async () => {
      const miro = miroWith({ users: [] });

      const error = await connectorError(() => grant("editor"));

      expect(error.data.payload).toMatchObject({ reason: "member_changed" });
      expect(miro.writes()).toEqual([]);
    });

    it("a board Miro doesn't have", async () => {
      const miro = miroWith({ boardMembers: {} });

      const error = await connectorError(() => grant("editor"));

      expect(error.data).toMatchObject({
        payload: { boardId: BOARD_ID, status: 404 },
        type: "validation_error",
      });
      expect(miro.writes()).toEqual([]);
    });

    it("a role on the board the connector doesn't know", async () => {
      const miro = miroWith({ prior: "guest" });

      const error = await connectorError(() => grant("editor"));

      expect(error.data).toMatchObject({
        payload: { role: "guest" },
        type: "validation_error",
      });
      expect(miro.writes()).toEqual([]);
    });
  });

  it("logs neither the token nor the secret's name nor the email", async () => {
    const recorded = recordLogger();
    miroWith();

    await grant("viewer");

    const seen = recorded.seen();
    for (const secret of [...NEVER_SHOWN, EMAIL]) {
      expect(seen).not.toContain(secret);
    }
  });
});

describe("a revoke", () => {
  // The member is where the grant left them: the higher of their prior
  // role and the request's.
  describe.each(PRIOR)("to %s", (prior) => {
    it.each(GRANTED)("from %s restores the prior role", async (own) => {
      const granted = rank(own) > rank(prior) ? own : prior;
      const miro = miroWith({ prior: granted });

      await revoke(own, prior);

      expect(roleOf(miro)).toBe(prior);
      const writes = miro.writes();
      if (granted === prior) {
        expect(writes).toEqual([]);
      } else if (prior === "none") {
        expect(writes).toEqual([
          { body: undefined, method: "DELETE", path: MEMBER_PATH },
        ]);
      } else {
        expect(writes).toEqual([
          { body: { role: prior }, method: "PATCH", path: MEMBER_PATH },
        ]);
      }
    });
  });

  describe("with an overlapping grant", () => {
    it("lowers to the highest role a sibling still holds", async () => {
      const miro = miroWith({ prior: "editor" });

      await revoke("editor", "viewer", ["commenter"]);

      expect(roleOf(miro)).toBe("commenter");
    });

    it("leaves a sibling's equal or higher role in place", async () => {
      const miro = miroWith({ prior: "editor" });

      await revoke("commenter", "viewer", ["editor"]);

      expect(roleOf(miro)).toBe("editor");
      expect(miro.writes()).toEqual([]);
    });

    it("never lowers below the prior role", async () => {
      const miro = miroWith({ prior: "editor" });

      await revoke("editor", "commenter", ["viewer"]);

      expect(roleOf(miro)).toBe("commenter");
    });
  });

  describe("leaves a role changed outside P0 alone", () => {
    it.each([
      ["lowered during the grant", "editor", "viewer"],
      ["raised to co-owner during the grant", "editor", "coowner"],
    ])("%s", async (_, own, now) => {
      const miro = miroWith({ prior: now });

      await revoke(own as BoardRole, "none");

      expect(roleOf(miro)).toBe(now);
      expect(miro.writes()).toEqual([]);
    });

    it("never raises a role someone lowered", async () => {
      const miro = miroWith({ prior: "viewer" });

      await revoke("editor", "commenter");

      expect(roleOf(miro)).toBe("viewer");
      expect(miro.writes()).toEqual([]);
    });
  });

  it("is done when the member has already left the board", async () => {
    const miro = miroWith({ prior: "none" });

    await revoke("editor", "none");

    expect(miro.writes()).toEqual([]);
  });

  it("is done when the board is gone", async () => {
    const miro = miroWith({ boardMembers: {} });

    await revoke("editor", "none");

    expect(miro.writes()).toEqual([]);
  });

  // The connector user lost co-owner, so Miro refuses every change.
  it("fails as revoke failed after Miro keeps refusing, and never reports success", async () => {
    const miro = miroWith({ connectorRole: "editor", prior: "editor" });

    const error = await connectorError(() => revoke("editor", "none"));

    expect(error.data).toMatchObject({
      payload: {
        boardId: BOARD_ID,
        memberId: MEMBER_ID,
        missingRole: "coowner",
        revokeFailed: true,
      },
      type: "insufficient_privileges",
    });
    expect(error.message).toContain(`board ${BOARD_ID}`);
    expect(roleOf(miro)).toBe("editor");
    expect(miro.writes()).toHaveLength(REVOKE_ATTEMPTS);
  });

  it("succeeds when Miro accepts a retry after a 403", async () => {
    const miro = miroWith({
      failures: [
        { method: "DELETE", path: /\/members\//, status: 403, times: 1 },
      ],
      prior: "editor",
    });

    await revoke("editor", "none");

    expect(roleOf(miro)).toBe("none");
  });

  // Taking access away mustn't depend on the member, but a token for
  // another team would find nothing and be done, leaving the access.
  it("fails, and takes nothing, when the token belongs to another team", async () => {
    const miro = miroWith({ prior: "editor", teamId: "3458764688600000999" });

    const error = await connectorError(() => revoke("editor", "none"));

    expect(error.data.type).toBe("insufficient_privileges");
    expect(error.data.payload).not.toHaveProperty("reason");
    expect(miro.writes()).toEqual([]);
  });

  it("takes access back from a member whose email has changed", async () => {
    const miro = miroWith({
      prior: "editor",
      requester: { email: "someone-else@example.com" },
    });

    await revoke("editor", "none");

    expect(roleOf(miro)).toBe("none");
  });

  // P0 rolls a failed grant back with a call that still says `grant`.
  it("treats a grant without its own role as the rollback of a failed grant", async () => {
    const miro = miroWith({ prior: "editor" });

    await setRole("editor", { policies: [], priorRole: "none" });

    expect(roleOf(miro)).toBe("none");
  });
});

describe("the board access's router", () => {
  const setPolicies = (context: Record<string, unknown>) => {
    const { board } = connectorRouter.createCaller({ logger })["miro-ai"]
      .accesses;
    return board.setPoliciesForUser({
      // @ts-expect-error -- the tests send contexts that don't parse, on purpose.
      context,
      policies: [],
      userBody: USER_BODY,
      userId: MEMBER_ID,
    });
  };

  const CONTEXT = {
    boardId: BOARD_ID,
    email: EMAIL,
    operation: "revoke",
    priorRole: "none",
    requestId: "req-1",
    role: "editor",
    secret: AWS_SECRET,
    teamId: TEAM_ID,
  };

  it("revokes through the router", async () => {
    const miro = miroWith({ prior: "editor" });

    await setPolicies(CONTEXT);

    expect(roleOf(miro)).toBe("none");
  });

  // A grant whose record is lost must fail visibly, not read as "held none"
  // and remove a member who was there before P0 (spec section 4).
  it("refuses a context without the prior role, and changes nothing", async () => {
    const { priorRole: _, ...withoutPrior } = CONTEXT;
    const miro = miroWith({ prior: "editor" });

    await expect(setPolicies(withoutPrior)).rejects.toThrow();

    expect(roleOf(miro)).toBe("editor");
    expect(miro.calls()).toEqual([]);
  });

  it.each([
    ["a board id with a slash", { boardId: "uXjV/../x=" }],
    ["a role P0 never grants", { role: "coowner" }],
  ])("refuses %s", async (_, change) => {
    const miro = miroWith({ prior: "editor" });

    await expect(setPolicies({ ...CONTEXT, ...change })).rejects.toThrow();

    expect(miro.calls()).toEqual([]);
  });
});
