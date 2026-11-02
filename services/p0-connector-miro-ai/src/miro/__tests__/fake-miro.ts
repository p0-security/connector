/**
 * A Miro double for the client's tests and install validation's. Its answers
 * follow the shapes in Miro's REST API reference and what spec V1 saw
 * (2026-10-30), or the tests prove nothing:
 *
 * - it answers `https://api.miro.com` only;
 * - `Authorization` is `Bearer <token>`, and any other value answers 401;
 * - `GET /v1/oauth-token` answers the token's team, user and scopes;
 * - `GET /v2/boards?team_id=` pages with `limit` (at most 50) and
 *   `offset`, and gives each board the token's user's
 *   `currentUserMembership`, or `null` for a board reached only through
 *   team access;
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

export type FakeMiroState = {
  /** The access token Miro accepts. The fixtures' `TOKEN` by default. */
  token?: string;
  /** The team the token was installed into. The fixtures' `TEAM_ID` by default. */
  teamId?: string;
  /** The token's scopes. Every scope the connector needs by default. */
  scopes?: string[];
  boards?: FakeBoard[];
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

export const newFakeMiro = (state: FakeMiroState = {}) => {
  const json = (body: unknown): Response => {
    const text = JSON.stringify(body);
    return new Response(
      state.numericIds ? text.replace(/"id":"([0-9]+)"/g, '"id":$1') : text,
      { status: 200, headers: { "content-type": "application/json" } }
    );
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
    if (method !== "GET") return errorAnswer(404, "Not found");
    const teamId = state.teamId ?? TEAM_ID;

    if (url.pathname === "/v1/oauth-token") {
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

    if (url.pathname === "/v2/boards") {
      const query = url.searchParams;
      const limit = Number(query.get("limit") ?? 20);
      const offset = Number(query.get("offset") ?? 0);
      if (limit > 50) return errorAnswer(400, "limit must be at most 50");
      const all = query.get("team_id") === teamId ? (state.boards ?? []) : [];
      const data = all
        .slice(offset, offset + limit)
        .map(({ id, name, role }) => ({
          id,
          type: "board",
          name: name ?? id,
          currentUserMembership:
            role === null ? null : { id: USER_ID, role, type: "board_member" },
        }));
      return json({
        data,
        limit,
        offset,
        size: data.length,
        total: all.length,
        type: "list",
      });
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
