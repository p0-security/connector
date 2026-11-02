import { ConnectorError, type Logger } from "@p0security/connector-core";
import { setTimeout as sleep } from "node:timers/promises";
import { z } from "zod";

import { failureFacts } from "../failure.ts";

/** Miro's REST API host. The connector calls no other. */
export const MIRO_HOST = "api.miro.com";

/** How long Miro has to answer a call, its body included. */
export const MIRO_TIMEOUT_MS = 10_000;

/** The most of a 2xx answer the connector reads. */
export const MAX_ANSWER_BYTES = 2 * 1024 * 1024;

/** The most of an error answer the connector reads, then drops. */
export const MAX_ERROR_BYTES = 16 * 1024;

/** How many times a call is made when Miro answers 429, the first included. */
export const MAX_ATTEMPTS = 3;

/**
 * The longest the connector waits before trying a 429'd call again, in
 * seconds, whatever `Retry-After` says. A longer wait is P0's to make: the
 * last 429 fails with `rate_limited` and its `retryAfter`.
 */
export const MAX_RETRY_WAIT_SECONDS = 2;

/** The wait before the next try when a 429 says nothing, in seconds. */
const DEFAULT_RETRY_WAIT_SECONDS = 1;

/** Boards per page: the most `GET /v2/boards` takes. */
export const BOARDS_PAGE_SIZE = 50;

/** The most pages of boards the connector reads before giving up. */
export const MAX_BOARD_PAGES = 200;

/** Members per page of a team's or a board's members. */
export const MEMBERS_PAGE_SIZE = 50;

/** The most pages of members the connector reads before giving up. */
export const MAX_MEMBER_PAGES = 200;

type Method = "DELETE" | "GET" | "PATCH" | "POST";

/**
 * What a call is, for its messages and its log lines. `route` is the path
 * as Miro's API reference writes it, with `{name}` for each id, so neither
 * carries an id.
 */
export type MiroCall = { method: Method; route: `/v${1 | 2}/${string}` };

/**
 * Every call the connector may make, and nothing else: the allowlist is
 * closed. Install validation only reads. The board access also adds,
 * changes and removes board members, and never anything else.
 */
export const MIRO_ROUTES = {
  addBoardMembers: { method: "POST", route: "/v2/boards/{board_id}/members" },
  getBoardMembers: { method: "GET", route: "/v2/boards/{board_id}/members" },
  getBoards: { method: "GET", route: "/v2/boards" },
  getOAuthToken: { method: "GET", route: "/v1/oauth-token" },
  getTeamUserConnections: {
    method: "GET",
    route: "/v1/teams/{team_id}/user-connections",
  },
  getUser: { method: "GET", route: "/v2/users/{user_id}" },
  removeBoardMember: {
    method: "DELETE",
    route: "/v2/boards/{board_id}/members/{board_member_id}",
  },
  updateBoardMember: {
    method: "PATCH",
    route: "/v2/boards/{board_id}/members/{board_member_id}",
  },
} as const satisfies Record<string, MiroCall>;

export type RouteName = keyof typeof MIRO_ROUTES;

/** Why an answer wasn't one Miro gives. `endless` is the pager's. */
export type UnexpectedAnswer =
  "endless" | "not_json" | "too_large" | "wrong_shape";

/** How a call failed. */
export type MiroFailure =
  /** An answer outside 2xx. */
  | {
      kind: "status";
      status: number;
      /** For a 429, how many seconds to wait, from `Retry-After`. */
      retryAfter?: number;
    }
  /** No answer: `code` and `name` are Node's, and say what happened. */
  | {
      kind: "unreachable";
      timedOut: boolean;
      code?: number | string;
      name?: string;
    }
  /** A 2xx with a body Miro wouldn't send. */
  | { kind: "unexpected"; reason: UnexpectedAnswer };

/**
 * A Miro call that failed.
 *
 * It holds the call's template and how it failed, and nothing of the
 * request: not the URL, whose query carries a team id, and not the headers,
 * which carry the token. Nor a `cause`: `fetch`'s errors can quote the
 * request.
 */
export class MiroError extends Error {
  constructor(
    readonly call: MiroCall,
    readonly failure: MiroFailure
  ) {
    super(`Miro ${call.method} ${call.route}: ${failure.kind}`);
    this.name = "MiroError";
  }
}

/**
 * The answer's body as text, or `undefined` when it is longer than `cap`
 * bytes. A copy of the LaunchDarkly connector's `readBounded`: it reads as
 * the body arrives and drops it at the cap.
 */
export const readBounded = async (
  response: Response,
  cap: number
): Promise<string | undefined> => {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return Buffer.concat(chunks).toString("utf8");
    size += value.byteLength;
    if (size > cap) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
};

// `JSON.parse`'s reviver gets each value's source text as `context.source`
// (Node 21 and later), which TypeScript's lib doesn't declare yet.
type Reviver = (
  key: string,
  value: unknown,
  context?: { source: string }
) => unknown;
const parseWithSource = JSON.parse as (
  text: string,
  reviver: Reviver
) => unknown;

/**
 * `text` parsed as JSON, or `undefined` when it isn't JSON, with every
 * integer too large for a JavaScript number kept as its digits, a string.
 *
 * Miro sends some ids as JSON numbers above 2^53 (`/v2/users/{id}` and a
 * board member POST's answer, spec V1), which `JSON.parse` alone rounds to
 * another user's id. {@link miroId} then reads either form as a string.
 */
export const parseJson = (text: string): unknown => {
  try {
    return parseWithSource(text, (_key, value, context) =>
      typeof value === "number" &&
      !Number.isSafeInteger(value) &&
      context !== undefined &&
      /^-?[0-9]+$/.test(context.source)
        ? context.source
        : value
    );
  } catch {
    return undefined;
  }
};

/**
 * A Miro id, as a string, whichever way Miro sent it. A number that isn't a
 * safe integer is refused rather than read as a rounded id: only a runtime
 * without the reviver's source text would let one through.
 */
export const miroId = z.union([
  z.string().min(1),
  z
    .number()
    .refine(Number.isSafeInteger, "must be an id Miro sent exactly")
    .transform(String),
]);

/**
 * How many seconds a 429 says to wait, from `Retry-After` as a whole number
 * of seconds, or `undefined` when it isn't there as one.
 */
export const retryAfterSeconds = (headers: Headers): number | undefined => {
  const value = headers.get("retry-after")?.trim();
  return value !== undefined && /^[0-9]+$/.test(value)
    ? Number(value)
    : undefined;
};

/** Waits `seconds`. Tests pass one that doesn't. */
export type Pause = (seconds: number) => Promise<void>;

const realPause: Pause = (seconds) => sleep(seconds * 1000);

/** Where a parse went wrong, never what it held. */
const issuesOf = ({ issues }: z.ZodError) =>
  issues.map(({ code, path }) => ({ code, path: path.map(String).join(".") }));

/** What a call takes, beside its route. */
type CallOptions = {
  /** The value of each `{name}` in the route. Each is encoded as a segment. */
  params?: Readonly<Record<string, string>>;
  query?: Readonly<Record<string, string>>;
};

/** What a read takes. */
export type ReadRequest<T> = CallOptions & {
  route: RouteName;
  answer: z.ZodType<T>;
};

/**
 * What a write takes. `answer` is the shape of its 2xx answer, or
 * `undefined` for one whose answer the connector doesn't read, such as a
 * DELETE's empty 204.
 */
export type WriteRequest<T> = CallOptions & {
  route: RouteName;
  body?: unknown;
  answer?: z.ZodType<T>;
};

/** Miro's REST API, as the connector user's access token. */
export type MiroApi = {
  /** A read, whose 2xx answer must be `answer`'s shape. */
  read: <T>(request: ReadRequest<T>) => Promise<T>;
  /** A write, sent once, with its body as JSON. */
  write: <T = undefined>(request: WriteRequest<T>) => Promise<T | undefined>;
  /** The error for an answer Miro wouldn't give, logged. */
  unexpected: (call: MiroCall, reason: UnexpectedAnswer) => MiroError;
};

/**
 * `route` with each `{name}` replaced by its value in `params`, encoded as
 * a path segment. A missing value throws: a route can't go out half-filled.
 */
const fillRoute = (
  route: string,
  params: Readonly<Record<string, string>>
): string =>
  route.replace(/\{([a-z_]+)\}/g, (_match, name: string) => {
    const value = params[name];
    if (value === undefined || value === "") {
      throw new Error(`the route's ${name} has no value`);
    }
    return encodeURIComponent(value);
  });

/**
 * Makes Miro calls with the connector user's access token, as
 * `Authorization: Bearer <token>`.
 *
 * The token lives only in this closure and in the header it sends: nothing
 * that holds it is returned, logged or thrown.
 *
 * Every call:
 * - is one of {@link MIRO_ROUTES}, sent to `https://api.miro.com`.
 * - gives up after {@link MIRO_TIMEOUT_MS}, its body included.
 * - follows no redirect, since the call carries the token: a 3xx is a
 *   failed status, and its body isn't read.
 * - reads at most {@link MAX_ANSWER_BYTES} of a 2xx, and drops an error's
 *   body unread past {@link MAX_ERROR_BYTES}: Miro's messages can echo what
 *   was asked.
 * - on a 429, waits `Retry-After` (at most {@link MAX_RETRY_WAIT_SECONDS})
 *   and tries again, {@link MAX_ATTEMPTS} times in all. Nothing else is
 *   tried again: P0 decides.
 *
 * A log line names the call by its route, never by its URL.
 */
export const newMiroApi = ({
  token,
  logger,
  pause = realPause,
}: {
  token: string;
  logger: Logger;
  pause?: Pause;
}): MiroApi => {
  const origin = `https://${MIRO_HOST}`;

  const unexpected = (
    call: MiroCall,
    reason: UnexpectedAnswer,
    fields: Record<string, unknown> = {}
  ) => {
    logger.warn(
      { method: call.method, reason, route: call.route, ...fields },
      "Miro's answer isn't one Miro gives"
    );
    return new MiroError(call, { kind: "unexpected", reason });
  };

  /**
   * `fetch` throws a bare "fetch failed" and keeps what happened in `cause`.
   * Either is described, never kept: both can quote the request.
   */
  const unreachable = (call: MiroCall, error: unknown) => {
    const cause: unknown =
      error instanceof Error && error.cause !== undefined ? error.cause : error;
    const { code, name } = failureFacts(cause);
    const failure: MiroFailure = {
      kind: "unreachable",
      timedOut: error instanceof Error && error.name === "TimeoutError",
      ...(code === undefined ? {} : { code }),
      ...(name === undefined ? {} : { name }),
    };
    logger.warn(
      { method: call.method, route: call.route, ...failure },
      "Miro call got no answer"
    );
    return new MiroError(call, failure);
  };

  /** One try: the 2xx answer's text, or `undefined` when over the cap. */
  const exchange = async (
    call: MiroCall,
    { path, query, body }: Outgoing
  ): Promise<string | undefined> => {
    const { method, route } = call;
    const search =
      Object.keys(query).length > 0
        ? `?${new URLSearchParams(query).toString()}`
        : "";
    const fail = (error: unknown): never => {
      throw unreachable(call, error);
    };

    const response = await fetch(`${origin}${path}${search}`, {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      method,
      redirect: "manual",
      signal: AbortSignal.timeout(MIRO_TIMEOUT_MS),
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }).catch(fail);

    const { status } = response;
    if (status >= 200 && status < 300) {
      const text = await readBounded(response, MAX_ANSWER_BYTES).catch(fail);
      logger.debug({ method, route, status }, "Miro call succeeded");
      return text;
    }

    // The body is drained, never kept: Miro's error messages can echo the
    // request.
    await (
      status >= 400
        ? readBounded(response, MAX_ERROR_BYTES)
        : response.body?.cancel()
    )?.catch(() => undefined);
    const retryAfter =
      status === 429 ? retryAfterSeconds(response.headers) : undefined;
    logger.debug(
      {
        method,
        route,
        status,
        ...(retryAfter === undefined ? {} : { retryAfter }),
      },
      "Miro call answered"
    );
    throw new MiroError(call, {
      kind: "status",
      status,
      ...(retryAfter === undefined ? {} : { retryAfter }),
    });
  };

  /**
   * The call, tried again after a 429 as {@link newMiroApi} says. A 429
   * means Miro didn't act on the call, so a write is tried again too.
   */
  const withBackoff = async (
    call: MiroCall,
    outgoing: Outgoing
  ): Promise<string | undefined> => {
    for (let attempt = 1; ; attempt++) {
      try {
        return await exchange(call, outgoing);
      } catch (error) {
        const rateLimited =
          error instanceof MiroError &&
          error.failure.kind === "status" &&
          error.failure.status === 429;
        if (!rateLimited || attempt >= MAX_ATTEMPTS) throw error;
        const asked =
          error.failure.kind === "status"
            ? error.failure.retryAfter
            : undefined;
        const wait = Math.min(
          asked ?? DEFAULT_RETRY_WAIT_SECONDS * 2 ** (attempt - 1),
          MAX_RETRY_WAIT_SECONDS
        );
        logger.info(
          { attempt, method: call.method, route: call.route, wait },
          "Miro limited the call, so it waits and tries again"
        );
        await pause(wait);
      }
    }
  };

  /** The route's call, refused when it isn't on the allowlist. */
  const callOf = (name: RouteName): MiroCall => {
    const call: MiroCall | undefined = Object.prototype.hasOwnProperty.call(
      MIRO_ROUTES,
      name
    )
      ? MIRO_ROUTES[name]
      : undefined;
    if (call === undefined) {
      throw new ConnectorError({
        message:
          "The connector refused to send a Miro call outside its allowlist. Contact P0 support.",
        payload: {},
        type: "validation_error",
      });
    }
    return call;
  };

  /** The 2xx answer's text read as `answer`'s shape. */
  const parseAnswer = <T>(
    call: MiroCall,
    text: string | undefined,
    answer: z.ZodType<T>
  ): T => {
    if (text === undefined) throw unexpected(call, "too_large");
    const json = parseJson(text);
    if (json === undefined) throw unexpected(call, "not_json");
    const parsed = answer.safeParse(json);
    if (!parsed.success) {
      throw unexpected(call, "wrong_shape", {
        issues: issuesOf(parsed.error),
      });
    }
    return parsed.data;
  };

  return {
    read: async ({ route: name, params = {}, query = {}, answer }) => {
      const call = callOf(name);
      const path = fillRoute(call.route, params);
      return parseAnswer(
        call,
        await withBackoff(call, { path, query }),
        answer
      );
    },

    write: async ({ route: name, params = {}, query = {}, body, answer }) => {
      const call = callOf(name);
      const path = fillRoute(call.route, params);
      const text = await withBackoff(call, { body, path, query });
      return answer === undefined ? undefined : parseAnswer(call, text, answer);
    },

    unexpected: (call, reason) => unexpected(call, reason),
  };
};

/** What a call sends: its filled path, its query and its JSON body. */
type Outgoing = {
  path: string;
  query: Readonly<Record<string, string>>;
  body?: unknown;
};

// `GET /v1/oauth-token`'s answer, as much of it as the connector reads.
const tokenInfo = z.object({
  scopes: z.array(z.string()),
  team: z.object({ id: miroId, name: z.string().optional() }),
  user: z.object({ id: miroId }),
});

/** What `GET /v1/oauth-token` says of the access token. */
export type TokenInfo = {
  /** The team the token was installed into. */
  teamId: string;
  /** The team's name, for messages. Its id when Miro gives none. */
  teamName: string;
  /** The connector user, whom the token acts as. */
  userId: string;
  /** The scopes the token was issued with. */
  scopes: string[];
};

// One page of `GET /v2/boards`. A board the token's user reaches only
// through team access has `currentUserMembership: null` (spec V1).
const boardsPage = z.object({
  data: z.array(
    z.object({
      id: miroId,
      name: z.string().optional(),
      currentUserMembership: z
        .object({ role: z.string() })
        .nullable()
        .optional(),
    })
  ),
  total: z.number().int().nonnegative(),
});

/** The roles that let the connector user share a board. */
export const SHARING_ROLES: ReadonlySet<string> = new Set(["owner", "coowner"]);

/** A board the connector user can share. */
export type ShareableBoard = { id: string; name: string };

// One page of `GET /v1/teams/{team_id}/user-connections`: each member's
// user id and team role, and no email (spec V1). Its own `id` is the
// connection's, not the user's.
const userConnectionsPage = z.object({
  data: z.array(z.object({ user: z.object({ id: miroId }) })),
});

// `GET /v2/users/{user_id}`. `state` is `not_registered` for someone
// invited to the team who hasn't created a Miro account yet (spec V1).
const user = z.object({
  id: miroId,
  email: z.string().optional(),
  state: z.string().optional(),
});

/** A Miro user, as the connector reads one. */
export type MiroUser = z.infer<typeof user>;

// One page of `GET /v2/boards/{board_id}/members`. A member's id is their
// Miro user id (spec V1). Only direct members are listed: someone who
// reaches the board through team or link access isn't.
const boardMembersPage = z.object({
  data: z.array(z.object({ id: miroId, role: z.string() })),
  total: z.number().int().nonnegative(),
});

/** A board's direct member: their user id and their role on the board. */
export type BoardMember = { id: string; role: string };

// `POST /v2/boards/{board_id}/members`: the member ids added, as JSON
// numbers above 2^53 (spec V1).
const addedMembers = z.object({ successful: z.array(miroId) });

/** The Miro calls the connector makes, typed. */
export type MiroClient = {
  fetchTokenInfo: () => Promise<TokenInfo>;
  /**
   * How many of the team's boards the token's user owns or co-owns, read
   * {@link BOARDS_PAGE_SIZE} to a page.
   */
  countShareableBoards: (teamId: string) => Promise<number>;
  /**
   * The team's boards the token's user owns or co-owns, each with its id
   * and name, read {@link BOARDS_PAGE_SIZE} to a page.
   */
  listShareableBoards: (teamId: string) => Promise<ShareableBoard[]>;
  /** The user id of every member of the team, invited ones included. */
  listTeamMemberIds: (teamId: string) => Promise<string[]>;
  /** The user, or `undefined` when Miro has no user with the id. */
  fetchUser: (userId: string) => Promise<MiroUser | undefined>;
  /** Every direct member of the board. */
  listBoardMembers: (boardId: string) => Promise<BoardMember[]>;
  /** Adds the user with `email` to the board at `role`. Their member id. */
  addBoardMember: (
    boardId: string,
    { email, role }: { email: string; role: string }
  ) => Promise<string>;
  /** Changes a member's role on the board. */
  setBoardMemberRole: (
    boardId: string,
    memberId: string,
    role: string
  ) => Promise<void>;
  /** Removes a member from the board. Only their direct role goes. */
  removeBoardMember: (boardId: string, memberId: string) => Promise<void>;
};

/** Whether `error` is Miro answering `status`. */
export const isStatus = (error: unknown, status: number): error is MiroError =>
  error instanceof MiroError &&
  error.failure.kind === "status" &&
  error.failure.status === status;

/** What `read` answers, or `undefined` when Miro answers 404. */
const unlessNotFound = async <T>(read: () => Promise<T>) => {
  try {
    return await read();
  } catch (error) {
    if (isStatus(error, 404)) return undefined;
    throw error;
  }
};

export const newMiroClient = (api: MiroApi): MiroClient => {
  /**
   * Every item of a paged list, `MEMBERS_PAGE_SIZE` to a page, until a page
   * is short or `total` is reached. Fails rather than read forever.
   */
  const readAll = async <Item>(
    call: MiroCall,
    readPage: (query: Record<string, string>) => Promise<{
      data: Item[];
      total?: number;
    }>,
    { pageSize, maxPages }: { pageSize: number; maxPages: number }
  ): Promise<Item[]> => {
    const items: Item[] = [];
    for (let page = 0; page < maxPages; page++) {
      const offset = page * pageSize;
      const { data, total } = await readPage({
        limit: String(pageSize),
        offset: String(offset),
      });
      items.push(...data);
      const done =
        data.length === 0 ||
        (total === undefined
          ? data.length < pageSize
          : offset + data.length >= total);
      if (done) return items;
    }
    throw api.unexpected(call, "endless");
  };

  const listShareableBoards = async (
    teamId: string
  ): Promise<ShareableBoard[]> => {
    const all = await readAll(
      MIRO_ROUTES.getBoards,
      (query) =>
        api.read({
          route: "getBoards",
          query: { ...query, team_id: teamId },
          answer: boardsPage,
        }),
      { maxPages: MAX_BOARD_PAGES, pageSize: BOARDS_PAGE_SIZE }
    );
    return all
      .filter(({ currentUserMembership }) =>
        SHARING_ROLES.has(currentUserMembership?.role ?? "")
      )
      .map(({ id, name }) => ({ id, name: name ?? id }));
  };

  return {
    fetchTokenInfo: async () => {
      const { scopes, team, user } = await api.read({
        route: "getOAuthToken",
        answer: tokenInfo,
      });
      return {
        scopes,
        teamId: team.id,
        teamName: team.name ?? team.id,
        userId: user.id,
      };
    },

    countShareableBoards: async (teamId) =>
      (await listShareableBoards(teamId)).length,

    listShareableBoards,

    listTeamMemberIds: async (teamId) => {
      const connections = await readAll(
        MIRO_ROUTES.getTeamUserConnections,
        (query) =>
          api.read({
            route: "getTeamUserConnections",
            params: { team_id: teamId },
            query,
            answer: userConnectionsPage,
          }),
        { maxPages: MAX_MEMBER_PAGES, pageSize: MEMBERS_PAGE_SIZE }
      );
      return connections.map((connection) => connection.user.id);
    },

    fetchUser: (userId) =>
      unlessNotFound(() =>
        api.read({
          route: "getUser",
          params: { user_id: userId },
          answer: user,
        })
      ),

    listBoardMembers: (boardId) =>
      readAll(
        MIRO_ROUTES.getBoardMembers,
        (query) =>
          api.read({
            route: "getBoardMembers",
            params: { board_id: boardId },
            query,
            answer: boardMembersPage,
          }),
        { maxPages: MAX_MEMBER_PAGES, pageSize: MEMBERS_PAGE_SIZE }
      ),

    addBoardMember: async (boardId, { email, role }) => {
      const answer = await api.write({
        route: "addBoardMembers",
        params: { board_id: boardId },
        body: { emails: [email], role },
        answer: addedMembers,
      });
      const [memberId, ...others] = answer?.successful ?? [];
      if (memberId === undefined || others.length > 0) {
        throw api.unexpected(MIRO_ROUTES.addBoardMembers, "wrong_shape");
      }
      return memberId;
    },

    setBoardMemberRole: async (boardId, memberId, role) => {
      await api.write({
        route: "updateBoardMember",
        params: { board_id: boardId, board_member_id: memberId },
        body: { role },
      });
    },

    removeBoardMember: async (boardId, memberId) => {
      await api.write({
        route: "removeBoardMember",
        params: { board_id: boardId, board_member_id: memberId },
      });
    },
  };
};
