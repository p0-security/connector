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

type Method = "GET";

/**
 * What a call is, for its messages and its log lines. `route` is the path
 * as Miro's API reference writes it, so neither carries an id.
 */
export type MiroCall = { method: Method; route: `/v${1 | 2}/${string}` };

/**
 * Every call the connector may make, and nothing else: the allowlist is
 * closed. The skeleton reads only; the board access adds its own (INT-1110).
 */
export const MIRO_ROUTES = {
  getBoards: { method: "GET", route: "/v2/boards" },
  getOAuthToken: { method: "GET", route: "/v1/oauth-token" },
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

/** What a read takes. */
export type ReadRequest<T> = {
  route: RouteName;
  query?: Readonly<Record<string, string>>;
  answer: z.ZodType<T>;
};

/** Miro's REST API, as the connector user's access token. */
export type MiroApi = {
  /** A read, whose 2xx answer must be `answer`'s shape. */
  read: <T>(request: ReadRequest<T>) => Promise<T>;
  /** The error for an answer Miro wouldn't give, logged. */
  unexpected: (call: MiroCall, reason: UnexpectedAnswer) => MiroError;
};

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
    query: Readonly<Record<string, string>>
  ): Promise<string | undefined> => {
    const { method, route } = call;
    const search =
      Object.keys(query).length > 0
        ? `?${new URLSearchParams(query).toString()}`
        : "";
    const fail = (error: unknown): never => {
      throw unreachable(call, error);
    };

    const response = await fetch(`${origin}${route}${search}`, {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
      method,
      redirect: "manual",
      signal: AbortSignal.timeout(MIRO_TIMEOUT_MS),
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

  /** The call, tried again after a 429 as {@link newMiroApi} says. */
  const withBackoff = async (
    call: MiroCall,
    query: Readonly<Record<string, string>>
  ): Promise<string | undefined> => {
    for (let attempt = 1; ; attempt++) {
      try {
        return await exchange(call, query);
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

  return {
    read: async ({ route: name, query = {}, answer }) => {
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
      const text = await withBackoff(call, query);
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
    },

    unexpected: (call, reason) => unexpected(call, reason),
  };
};

// `GET /v1/oauth-token`'s answer, as much of it as the connector reads.
const tokenInfo = z.object({
  scopes: z.array(z.string()),
  team: z.object({ id: miroId }),
  user: z.object({ id: miroId }),
});

/** What `GET /v1/oauth-token` says of the access token. */
export type TokenInfo = {
  /** The team the token was installed into. */
  teamId: string;
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
      currentUserMembership: z
        .object({ role: z.string() })
        .nullable()
        .optional(),
    })
  ),
  total: z.number().int().nonnegative(),
});

/** The roles that let the connector user share a board. */
const SHARING_ROLES: ReadonlySet<string> = new Set(["owner", "coowner"]);

/** The Miro calls the connector makes, typed. */
export type MiroClient = {
  fetchTokenInfo: () => Promise<TokenInfo>;
  /**
   * How many of the team's boards the token's user owns or co-owns, read
   * {@link BOARDS_PAGE_SIZE} to a page.
   */
  countShareableBoards: (teamId: string) => Promise<number>;
};

export const newMiroClient = (api: MiroApi): MiroClient => ({
  fetchTokenInfo: async () => {
    const { scopes, team, user } = await api.read({
      route: "getOAuthToken",
      answer: tokenInfo,
    });
    return { scopes, teamId: team.id, userId: user.id };
  },

  countShareableBoards: async (teamId) => {
    let count = 0;
    for (let page = 0; page < MAX_BOARD_PAGES; page++) {
      const offset = page * BOARDS_PAGE_SIZE;
      const { data, total } = await api.read({
        route: "getBoards",
        query: {
          limit: String(BOARDS_PAGE_SIZE),
          offset: String(offset),
          team_id: teamId,
        },
        answer: boardsPage,
      });
      count += data.filter(({ currentUserMembership }) =>
        SHARING_ROLES.has(currentUserMembership?.role ?? "")
      ).length;
      if (data.length === 0 || offset + data.length >= total) return count;
    }
    throw api.unexpected(MIRO_ROUTES.getBoards, "endless");
  },
});
