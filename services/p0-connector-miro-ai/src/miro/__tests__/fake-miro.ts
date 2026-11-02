/**
 * A Miro double for the client's tests, install validation's and the board
 * access's. Its answers follow the shapes in Miro's REST API reference and
 * what spec V1 saw (2026-10-30), or the tests prove nothing:
 *
 * - it answers `https://api.miro.com` only;
 * - `Authorization` is `Bearer <token>`, and any other value answers 401;
 * - `GET /v1/oauth-token` answers the token's team, user and scopes;
 * - `GET /v2/boards?team_id=` pages with `limit` (at most 50) and
 *   `offset`, and gives each board the token's user's
 *   `currentUserMembership`, or `null` for a board reached only through
 *   team access;
 * - `GET /v1/teams/{team_id}/user-connections` pages the team's members,
 *   each with its user id and team role, and no email;
 * - `GET /v2/users/{user_id}` answers the user's email and `state`, which is
 *   `not_registered` for someone invited who hasn't signed up;
 * - `GET /v2/boards/{board_id}/members` pages the board's direct members;
 * - `POST /v2/boards/{board_id}/members` adds a team member by email and
 *   answers `{ successful: [<id>] }`. It refuses `viewer` with 403, as
 *   Miro does (spec V1);
 * - `PATCH` and `DELETE /v2/boards/{board_id}/members/{board_member_id}`
 *   change and remove a member. Every write answers 403 unless the token's
 *   user is the board's owner or co-owner;
 * - with `numericIds`, ids go out as JSON numbers, as `/v2/users/{id}` and a
 *   member POST's answer send them, which `JSON.parse` alone rounds;
 * - an error's body is `{ status, code, message, type: "error" }`;
 * - any other route, or method, answers 404.
 */
import { vi } from "vitest";

import { TEAM_ID, TOKEN, USER_ID } from "../../__tests__/fixtures.ts";

/** A board, as the token's user sees it. */
export type FakeBoard = {
  id: string;
  name?: string;
  /** The token's user's role on the board, or `null` for team access only. */
  role: string | null;
};

/** A Miro user. */
export type FakeUser = {
  id: string;
  email: string;
  /** `registered` by default. */
  state?: "not_registered" | "registered";
};

/** A board's direct member. */
export type FakeMember = { id: string; role: string };

/** A call the fake fails, `times` times (always, by default), with `status`. */
export type FakeFailure = {
  method: string;
  path: RegExp;
  status: number;
  times?: number;
};

export type FakeMiroState = {
  /** The access token Miro accepts. The fixtures' `TOKEN` by default. */
  token?: string;
  /** The team the token was installed into. The fixtures' `TEAM_ID` by default. */
  teamId?: string;
  /** The token's scopes. Every scope the connector needs by default. */
  scopes?: string[];
  boards?: FakeBoard[];
  /** Every user Miro has. */
  users?: FakeUser[];
  /** The team's members, by user id. */
  teamMemberIds?: string[];
  /** Each board's direct members, by board id. The token's user among them. */
  boardMembers?: Record<string, FakeMember[]>;
  /** Calls to fail, matched in order. */
  failures?: FakeFailure[];
  /** Send ids as JSON numbers rather than strings. */
  numericIds?: boolean;
};

/** Every scope the connector needs. */
export const ALL_SCOPES = ["boards:read", "boards:write", "team:read"];

/** `count` boards whose role is `role`, with ids of their own. */
export const boards = (count: number, role: string | null): FakeBoard[] =>
  Array.from({ length: count }, (_, index) => ({
    id: `uXjV${role ?? "team"}${index}=`,
    role,
  }));

/** Miro's error body. */
export const errorAnswer = (status: number, message: string): Response =>
  new Response(
    JSON.stringify({ status, code: `error${status}`, message, type: "error" }),
    { status, headers: { "content-type": "application/json" } }
  );

/** The roles that let the token's user change a board's members. */
const SHARING = new Set(["coowner", "owner"]);

export const newFakeMiro = (state: FakeMiroState = {}) => {
  const json = (body: unknown, status = 200): Response => {
    const text = JSON.stringify(body);
    return new Response(
      state.numericIds
        ? text
            .replace(/"id":"([0-9]+)"/g, '"id":$1')
            .replace(/"successful":\["([0-9]+)"\]/g, '"successful":[$1]')
        : text,
      { status, headers: { "content-type": "application/json" } }
    );
  };

  /** A page of `all`, by the query's `limit` and `offset`. */
  const pageOf = <T>(all: T[], query: URLSearchParams) => {
    const limit = Number(query.get("limit") ?? 20);
    const offset = Number(query.get("offset") ?? 0);
    return { data: all.slice(offset, offset + limit), limit, offset };
  };

  /** The failure planned for the call, used up once its `times` run out. */
  const plannedFailure = (method: string, path: string) => {
    const failure = state.failures?.find(
      (planned) =>
        planned.method === method &&
        planned.path.test(path) &&
        (planned.times === undefined || planned.times > 0)
    );
    if (failure?.times !== undefined) failure.times -= 1;
    return failure;
  };

  const answer = async (
    input: string,
    init: RequestInit = {}
  ): Promise<Response> => {
    const url = new URL(input);
    if (url.origin !== "https://api.miro.com") {
      throw new Error("the fake answers https://api.miro.com only");
    }
    const method = init.method ?? "GET";
    const headers = new Headers(init.headers);
    if (headers.get("authorization") !== `Bearer ${state.token ?? TOKEN}`) {
      return errorAnswer(401, "Authorization failed");
    }
    const failure = plannedFailure(method, url.pathname);
    if (failure !== undefined) {
      return errorAnswer(failure.status, "Planned failure");
    }
    const teamId = state.teamId ?? TEAM_ID;
    const query = url.searchParams;

    if (method === "GET" && url.pathname === "/v1/oauth-token") {
      return json({
        type: "oauth_token",
        createdBy: { type: "user", name: "Connector", id: USER_ID },
        organization: {
          type: "organization",
          name: "P0",
          id: "3458764688600000001",
        },
        scopes: state.scopes ?? ALL_SCOPES,
        team: { type: "team", name: "Dev team", id: teamId },
        user: { type: "user", name: "Connector", id: USER_ID },
      });
    }

    if (method === "GET" && url.pathname === "/v2/boards") {
      const limit = Number(query.get("limit") ?? 20);
      if (limit > 50) return errorAnswer(400, "limit must be at most 50");
      const all = query.get("team_id") === teamId ? (state.boards ?? []) : [];
      const { data, offset } = pageOf(all, query);
      return json({
        data: data.map(({ id, name, role }) => ({
          id,
          type: "board",
          name: name ?? id,
          currentUserMembership:
            role === null ? null : { id: USER_ID, role, type: "board_member" },
        })),
        limit,
        offset,
        size: data.length,
        total: all.length,
        type: "list",
      });
    }

    const team = /^\/v1\/teams\/([^/]+)\/user-connections$/.exec(url.pathname);
    if (method === "GET" && team) {
      const all = team[1] === teamId ? (state.teamMemberIds ?? []) : [];
      const { data, limit, offset } = pageOf(all, query);
      return json({
        type: "list",
        limit,
        offset,
        size: data.length,
        data: data.map((id) => ({
          type: "team-user-connection",
          id: `connection-${id}`,
          role: "member",
          user: { type: "user", id },
        })),
      });
    }

    const userPath = /^\/v2\/users\/([^/]+)$/.exec(url.pathname);
    if (method === "GET" && userPath) {
      const found = state.users?.find(({ id }) => id === userPath[1]);
      if (found === undefined) return errorAnswer(404, "User not found");
      return json({
        type: "user",
        id: found.id,
        email: found.email,
        name: found.state === "not_registered" ? "NoName" : "Requester",
        state: found.state ?? "registered",
      });
    }

    const boardPath = /^\/v2\/boards\/([^/]+)\/members(?:\/([^/]+))?$/.exec(
      url.pathname
    );
    if (boardPath) {
      const boardId = decodeURIComponent(boardPath[1] ?? "");
      const memberId = boardPath[2];
      const members = state.boardMembers?.[boardId];
      if (members === undefined) return errorAnswer(404, "Board not found");
      const canShare = SHARING.has(
        members.find(({ id }) => id === USER_ID)?.role ?? ""
      );

      if (method === "GET" && memberId === undefined) {
        const { data, limit, offset } = pageOf(members, query);
        return json({
          data: data.map(({ id, role }) => ({
            id,
            name: "Member",
            role,
            type: "board_member",
          })),
          limit,
          offset,
          size: data.length,
          total: members.length,
          type: "list",
        });
      }

      if (method !== "GET" && !canShare) {
        return errorAnswer(403, "Insufficient permissions");
      }
      const body = JSON.parse(
        typeof init.body === "string" ? init.body : "{}"
      ) as {
        emails?: string[];
        role?: string;
      };

      if (method === "POST" && memberId === undefined) {
        if (body.role === "viewer") {
          return errorAnswer(403, "Cannot share with the viewer role");
        }
        const [email] = body.emails ?? [];
        const user = state.users?.find(
          (candidate) => candidate.email.toLowerCase() === email?.toLowerCase()
        );
        if (user === undefined || body.role === undefined) {
          return errorAnswer(400, "Invalid request");
        }
        members.push({ id: user.id, role: body.role });
        return json({ successful: [user.id], failed: [] }, 201);
      }

      const index = members.findIndex(({ id }) => id === memberId);
      if (memberId !== undefined && index === -1) {
        return errorAnswer(404, "Board member not found");
      }
      if (method === "PATCH" && memberId !== undefined) {
        if (body.role === undefined) return errorAnswer(400, "Invalid request");
        members[index] = { id: memberId, role: body.role };
        return json({ id: memberId, role: body.role, type: "board_member" });
      }
      if (method === "DELETE" && memberId !== undefined) {
        members.splice(index, 1);
        return new Response(null, { status: 204 });
      }
    }

    return errorAnswer(404, "Not found");
  };

  const fetchMock = vi.fn(answer);
  vi.stubGlobal("fetch", fetchMock);
  return {
    state,
    fetch: fetchMock,
    /** Each call's method and URL. */
    calls: () =>
      fetchMock.mock.calls.map(
        ([url, init]) => `${init?.method ?? "GET"} ${url}`
      ),
    /** Each write's method, path and body, in order. */
    writes: () =>
      fetchMock.mock.calls
        .filter(([, init]) => (init?.method ?? "GET") !== "GET")
        .map(([url, init]) => ({
          body:
            typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
          method: init?.method,
          path: decodeURIComponent(new URL(url).pathname),
        })),
    /**
     * Answers a call with `override`'s response when it gives one, and as
     * the fake does otherwise.
     */
    intercept: (
      override: (
        url: string
      ) => Promise<Response | undefined> | Response | undefined
    ) => {
      fetchMock.mockImplementation(
        async (url, init) => (await override(url)) ?? (await answer(url, init))
      );
    },
  };
};
