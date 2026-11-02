import { describe, expect, it, vi } from "vitest";

import {
  API,
  AWS_SECRET,
  TEAM_ID,
  USER_ID,
  connectorError,
  logger,
  stubToken,
} from "../../../__tests__/fixtures.ts";
import {
  type FakeMiroState,
  boards,
  newFakeMiro,
} from "../../../miro/__tests__/fake-miro.ts";
import { connectorRouter } from "../../../router.ts";

// The secret manager is `secrets.test.ts`'s business.
vi.mock("../../../secrets.ts");

const BOARD_ID = "uXjVOakxTk0=";
const MEMBER_ID = "3458764688981436603";
const OTHER_ID = "3458764688981436604";
const EMAIL = "requester@example.com";
const CONTEXT = { secret: AWS_SECRET, teamId: TEAM_ID };

const miroWith = (overrides: FakeMiroState = {}) =>
  newFakeMiro({
    numericIds: true,
    teamMemberIds: [USER_ID, OTHER_ID, MEMBER_ID],
    users: [
      { email: "connector@example.com", id: USER_ID },
      { email: "colleague@example.com", id: OTHER_ID },
      { email: EMAIL, id: MEMBER_ID },
    ],
    ...overrides,
  });

// Calling through the connector router also proves the query parses.
const list = (query: Record<string, unknown>) => {
  const { board } = connectorRouter.createCaller({ logger })["miro-ai"]
    .accesses;
  // @ts-expect-error -- some tests send queries that don't parse, on purpose.
  return board.list({ query });
};

stubToken();

describe("the member query", () => {
  const member = (email = EMAIL) =>
    list({ context: CONTEXT, email, type: "member" });

  it("finds the team's member with the email, ignoring case", async () => {
    miroWith();

    await expect(member("Requester@Example.com")).resolves.toEqual([
      { key: MEMBER_ID, value: EMAIL },
    ]);
  });

  it("reads members in turn until one matches", async () => {
    const miro = miroWith();

    await member();

    expect(
      miro.calls().filter((call) => call.startsWith(`GET ${API}/v2/users/`))
    ).toEqual([
      `GET ${API}/v2/users/${USER_ID}`,
      `GET ${API}/v2/users/${OTHER_ID}`,
      `GET ${API}/v2/users/${MEMBER_ID}`,
    ]);
  });

  it("pages through a large team", async () => {
    const many = Array.from(
      { length: 120 },
      (_, index) => `34587646889814${String(index).padStart(5, "0")}`
    );
    miroWith({
      teamMemberIds: [...many, MEMBER_ID],
      users: [{ email: EMAIL, id: MEMBER_ID }],
    });

    await expect(member()).resolves.toEqual([{ key: MEMBER_ID, value: EMAIL }]);
  });

  it("refuses with not_in_team when no member has the email, and invites nobody", async () => {
    const miro = miroWith();

    const error = await connectorError(() => member("stranger@example.com"));

    expect(error.data).toMatchObject({
      payload: { reason: "not_in_team" },
      type: "validation_error",
    });
    expect(miro.writes()).toEqual([]);
  });

  it("refuses with pending_invite when the member hasn't signed up", async () => {
    miroWith({
      users: [{ email: EMAIL, id: MEMBER_ID, state: "not_registered" }],
    });

    const error = await connectorError(() => member());

    expect(error.data.payload).toMatchObject({ reason: "pending_invite" });
  });
});

describe("the member-state query", () => {
  const memberState = () =>
    list({
      boardId: BOARD_ID,
      context: CONTEXT,
      memberId: MEMBER_ID,
      type: "member-state",
    });

  it("reports the member's role on the board", async () => {
    miroWith({
      boardMembers: {
        [BOARD_ID]: [
          { id: USER_ID, role: "coowner" },
          { id: MEMBER_ID, role: "commenter" },
        ],
      },
    });

    await expect(memberState()).resolves.toEqual([
      { key: "role", value: "commenter" },
    ]);
  });

  it("reports none for someone who isn't a direct member", async () => {
    miroWith({
      boardMembers: { [BOARD_ID]: [{ id: USER_ID, role: "owner" }] },
    });

    await expect(memberState()).resolves.toEqual([
      { key: "role", value: "none" },
    ]);
  });
});

describe("the boards query", () => {
  it("lists the team's boards the connector user owns or co-owns, by id and name", async () => {
    miroWith({
      boards: [
        { id: "uXjVa=", name: "[Public] Roadmap", role: "owner" },
        { id: "uXjVb=", name: "Private", role: "editor" },
        { id: "uXjVc=", name: "Team only", role: null },
        { id: "uXjVd=", name: "Design", role: "coowner" },
      ],
    });

    await expect(list({ context: CONTEXT, type: "boards" })).resolves.toEqual([
      { key: "uXjVa=", value: "[Public] Roadmap" },
      { key: "uXjVd=", value: "Design" },
    ]);
  });

  it("pages at 50", async () => {
    const miro = miroWith({
      boards: [...boards(60, "coowner"), ...boards(5, "viewer")],
    });

    const items = await list({ context: CONTEXT, type: "boards" });

    expect(items).toHaveLength(60);
    expect(
      miro.calls().filter((call) => call.startsWith(`GET ${API}/v2/boards?`))
    ).toEqual([
      `GET ${API}/v2/boards?limit=50&offset=0&team_id=${TEAM_ID}`,
      `GET ${API}/v2/boards?limit=50&offset=50&team_id=${TEAM_ID}`,
    ]);
  });
});

describe("every query", () => {
  it.each([
    { email: EMAIL, type: "member" },
    { boardId: BOARD_ID, memberId: MEMBER_ID, type: "member-state" },
    { type: "boards" },
  ])(
    "refuses with member_changed when the token is another team's ($type)",
    async (query) => {
      miroWith({ teamId: "3458764688600000999" });

      const error = await connectorError(() =>
        list({ context: CONTEXT, ...query })
      );

      expect(error.data.payload).toMatchObject({
        changed: "team",
        reason: "member_changed",
      });
    }
  );

  it("refuses a board id that could leave its path segment", async () => {
    const miro = miroWith();

    await expect(
      list({
        boardId: "../teams",
        context: CONTEXT,
        memberId: MEMBER_ID,
        type: "member-state",
      })
    ).rejects.toThrow();
    expect(miro.calls()).toEqual([]);
  });
});
