import {
  ConnectorError,
  type Logger,
  throwAssertNever,
} from "@p0security/connector-core";
import { z } from "zod";

import { type Instance, LAUNCHDARKLY_HOSTS } from "../account.ts";
import { failureFacts, renderFailure } from "../failure.ts";
import { BASE_ROLES_BY_RANK } from "./roles.ts";

/** Where LaunchDarkly's REST API lives under each instance's host. */
export const LAUNCHDARKLY_API = "/api/v2";

/**
 * The API version every call asks for, in `LD-API-Version`: the current one
 * in the spec's changelog when the connector was written (read 2026-10-17).
 * A token carries a version of its own, which the header overrides. Under
 * this one, lists page with `limit` and `offset`, 20 rows by default.
 */
export const LD_API_VERSION = "20240415";

/** How long LaunchDarkly has to answer a call, its body included. */
export const LAUNCHDARKLY_TIMEOUT_MS = 10_000;

/** The most of a 2xx answer the connector reads. */
export const MAX_ANSWER_BYTES = 2 * 1024 * 1024;

/**
 * The most of an error answer the connector reads, for LaunchDarkly's
 * `{ code, message }`.
 */
export const MAX_ERROR_BYTES = 16 * 1024;

/** The most of LaunchDarkly's error `message` a message quotes. */
export const MAX_QUOTED_MESSAGE = 300;

type Method = "GET" | "PATCH" | "POST";

/**
 * What a call is, for its messages and its log lines.
 *
 * `route` is the path as LaunchDarkly's API reference writes it, with
 * `{placeholders}` for the values, so neither a message nor a log line
 * carries a member id, a key or an email.
 */
export type LaunchDarklyCall = {
  method: Method;
  route: `${typeof LAUNCHDARKLY_API}/${string}`;
};

/**
 * Every call the connector may make, by the operation id LaunchDarkly's spec
 * gives it, and nothing else: the allowlist is closed. Three reads and one
 * write, all of them on every plan.
 */
export const LAUNCHDARKLY_ROUTES = {
  getCallerIdentity: { method: "GET", route: "/api/v2/caller-identity" },
  getMember: { method: "GET", route: "/api/v2/members/{id}" },
  getMembers: { method: "GET", route: "/api/v2/members" },
  patchMember: { method: "PATCH", route: "/api/v2/members/{id}" },
} as const satisfies Record<string, LaunchDarklyCall>;

type Routes = typeof LAUNCHDARKLY_ROUTES;

export type RouteName = keyof Routes;

const isRouteName = (name: string): name is RouteName =>
  Object.prototype.hasOwnProperty.call(LAUNCHDARKLY_ROUTES, name);

export type ReadRoute = {
  [Name in RouteName]: Routes[Name]["method"] extends "GET" ? Name : never;
}[RouteName];

export type WriteRoute = Exclude<RouteName, ReadRoute>;

type PlaceholdersOf<Route extends string> =
  Route extends `${string}{${infer Name}}${infer Rest}`
    ? Name | PlaceholdersOf<Rest>
    : never;

/** The values a route's placeholders take, by name. */
export type ParamsOf<Name extends RouteName> = Record<
  PlaceholdersOf<Routes[Name]["route"]>,
  string
>;

export type ParamsArg<Name extends RouteName> = [
  PlaceholdersOf<Routes[Name]["route"]>,
] extends [never]
  ? { params?: undefined }
  : { params: ParamsOf<Name> };

// `GET /members` only ever looks a member up by email: one `email:` filter,
// with no `,` that would add another filter.
const MEMBER_FILTER = /^email:[^,]+$/;

// The base roles the connector tests for and writes. Never `owner`, which
// P0 neither grants nor writes over. A string on the way in, so a caller
// may pass a role it read from LaunchDarkly, and checked before `fetch`.
const WRITTEN_BASE_ROLES: ReadonlySet<string> = new Set(
  BASE_ROLES_BY_RANK.filter((role) => role !== "owner")
);
const writtenBaseRole = z
  .string()
  .refine((role) => WRITTEN_BASE_ROLES.has(role), "must be a base role");

/**
 * `PATCH /members/{id}`'s body: a bare JSON Patch array, as the spec has it,
 * with exactly the operations the connector sends: `test` and `replace` on
 * `/role`, with a base role below `owner`.
 *
 * Any other path or operation, `remove` on `/role` and `move` or `copy`
 * among them, is refused.
 */
const memberJsonPatch = z
  .array(
    z.strictObject({
      op: z.enum(["replace", "test"]),
      path: z.literal("/role"),
      value: writtenBaseRole,
    })
  )
  .min(1);

const JSON_CONTENT = "application/json";

const WRITE_RULES = {
  patchMember: { body: memberJsonPatch, contentType: JSON_CONTENT },
} as const satisfies Record<
  WriteRoute,
  { body: z.ZodType; contentType: string }
>;

/** The body a write route takes. */
export type BodyOf<Name extends WriteRoute> = z.input<
  (typeof WRITE_RULES)[Name]["body"]
>;

/**
 * Why an answer wasn't one LaunchDarkly gives. `endless` and
 * `too_many_rows` are the pager's (`paged` in client.ts).
 */
export type UnexpectedAnswer =
  "endless" | "not_json" | "too_large" | "too_many_rows" | "wrong_shape";

/** How a call failed. */
export type LaunchDarklyFailure =
  /** An answer outside 2xx. */
  | {
      kind: "status";
      status: number;
      /** LaunchDarkly's `code` for the error, such as `forbidden`. */
      code?: string;
      /**
       * LaunchDarkly's `message`, cut short. Kept for a write only: a read's
       * can echo what it was asked, an email among it.
       */
      message?: string;
      /** For a 429, how many seconds to wait, from the answer's headers. */
      retryAfter?: number;
    }
  /** No answer: `code` and `name` are Node's, and say what happened. */
  | {
      kind: "unreachable";
      timedOut: boolean;
      code?: number | string;
      name?: string;
    }
  /** A 2xx with a body LaunchDarkly wouldn't send. */
  | { kind: "unexpected"; reason: UnexpectedAnswer };

const renderCallFailure = (failure: LaunchDarklyFailure) => {
  switch (failure.kind) {
    case "unreachable":
      return failure.timedOut
        ? "no answer in time"
        : `no answer (${renderFailure(failure) ?? "unknown"})`;
    case "status":
      return `answered ${failure.status}`;
    case "unexpected":
      return `unexpected answer (${failure.reason})`;
    default:
      throw throwAssertNever(failure);
  }
};

/**
 * A LaunchDarkly call that failed.
 *
 * It holds the call's template and how it failed, and nothing of the
 * request: not the URL, whose path and query carry ids and emails, and not
 * the headers, which carry the token. Nor a `cause`: `fetch`'s errors can
 * quote the request.
 */
export class LaunchDarklyError extends Error {
  constructor(
    readonly call: LaunchDarklyCall,
    readonly failure: LaunchDarklyFailure
  ) {
    super(
      `LaunchDarkly ${call.method} ${call.route}: ${renderCallFailure(failure)}`
    );
    this.name = "LaunchDarklyError";
  }
}

/** The status LaunchDarkly answered a failed call with, if it answered. */
export const statusOf = (error: unknown): number | undefined =>
  error instanceof LaunchDarklyError && error.failure.kind === "status"
    ? error.failure.status
    : undefined;

/** Whether LaunchDarkly answered a failed call with one of `statuses`. */
export const isStatus = (
  error: unknown,
  ...statuses: number[]
): error is LaunchDarklyError => {
  const status = statusOf(error);
  return status !== undefined && statuses.includes(status);
};

/**
 * One URL path segment. A copy of the Harbor connector's (its
 * src/harbor/api.ts), which refuses what `encodeURIComponent` leaves alone
 * and `fetch` would resolve: `.` and `..`, and an empty segment.
 */
export const segment = (value: string): string => {
  if (value === "" || value === "." || value === "..") {
    throw new ConnectorError({
      message:
        "The connector refused to send LaunchDarkly an empty or dot-only id or key in a URL path. Contact P0 support.",
      payload: {},
      type: "validation_error",
    });
  }
  return encodeURIComponent(value);
};

/**
 * The answer's body as text, or `undefined` when it is longer than `cap`
 * bytes. A copy of the Harbor connector's `readBounded`, with the cap as an
 * argument: it reads as the body arrives and drops it at the cap, so a body
 * of any length costs the connector no more than the cap.
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

/** The header's value as a whole number, or `undefined` when it isn't one. */
const wholeNumberIn = (headers: Headers, name: string): number | undefined => {
  const value = headers.get(name)?.trim();
  return value !== undefined && /^[0-9]+$/.test(value)
    ? Number(value)
    : undefined;
};

/**
 * How many seconds a 429 says to wait, as a number: `Retry-After` (seconds),
 * or the time `X-Ratelimit-Reset` or `X-Ratelimit-Auth-Token-Reset` names
 * (epoch milliseconds), whichever is latest, and never less than 0.
 * `undefined` when none of them is there as a number.
 */
export const retryAfterSeconds = (
  headers: Headers,
  now: number
): number | undefined => {
  const waits = [
    wholeNumberIn(headers, "retry-after"),
    ...["x-ratelimit-reset", "x-ratelimit-auth-token-reset"].map((name) => {
      const reset = wholeNumberIn(headers, name);
      return reset === undefined ? undefined : Math.ceil((reset - now) / 1000);
    }),
  ].filter((wait) => wait !== undefined);
  return waits.length === 0 ? undefined : Math.max(...waits, 0);
};

// LaunchDarkly's error body, `{ code, message, id }`. A field of the wrong
// type reads as absent.
const errorBody = z.object({
  code: z.string().optional().catch(undefined),
  message: z.string().optional().catch(undefined),
});

/** What an error answer says about itself. */
type ErrorDetails = { code?: string; message?: string };

/**
 * `text` parsed as JSON, or `undefined` when it isn't JSON, which no JSON
 * text parses to.
 */
export const parseJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

/** Where a parse went wrong, never what it held. */
const issuesOf = ({ issues }: z.ZodError) =>
  issues.map(({ code, path }) => ({ code, path: path.map(String).join(".") }));

/**
 * LaunchDarkly's message, as a message may quote it: control characters and
 * runs of whitespace become one space, and it stops at
 * {@link MAX_QUOTED_MESSAGE} characters.
 */
const quotable = (message: string): string | undefined => {
  const flat = message.replace(/[\p{Cc}\s]+/gu, " ").trim();
  if (flat === "") return undefined;
  return flat.length > MAX_QUOTED_MESSAGE
    ? `${flat.slice(0, MAX_QUOTED_MESSAGE)}...`
    : flat;
};

/** What a read takes. */
export type ReadRequest<Name extends ReadRoute, T> = {
  route: Name;
  query?: Readonly<Record<string, string>>;
  answer: z.ZodType<T>;
} & ParamsArg<Name>;

/** What a write takes. */
export type WriteRequest<Name extends WriteRoute, T> = {
  route: Name;
  body: BodyOf<Name>;
  answer: z.ZodType<T>;
} & ParamsArg<Name>;

/** LaunchDarkly's REST API, as the access token on one instance. */
export type LaunchDarklyApi = {
  /** The instance's host, which stands for the account in messages. */
  host: string;
  /** A read, whose 2xx answer must be `answer`'s shape. */
  read: <Name extends ReadRoute, T>(
    request: ReadRequest<Name, T>
  ) => Promise<T>;
  /** A write, whose 2xx answer must be `answer`'s shape. */
  write: <Name extends WriteRoute, T>(
    request: WriteRequest<Name, T>
  ) => Promise<T>;
  /**
   * The error for an answer LaunchDarkly wouldn't give, logged. For checks
   * the caller makes on answers that parsed.
   */
  unexpected: (
    call: LaunchDarklyCall,
    reason: UnexpectedAnswer
  ) => LaunchDarklyError;
};

/**
 * Makes LaunchDarkly calls with the account's access token, on the host its
 * instance names, with `Authorization: <token>` (no `Bearer`), as
 * LaunchDarkly takes it.
 *
 * The token lives only in this closure and in the header it sends: nothing
 * that holds it is returned, logged or thrown.
 *
 * Every call:
 * - is one of {@link LAUNCHDARKLY_ROUTES}, with each path value encoded as
 *   one segment. `GET /members` must carry one `email:` filter, and a
 *   write's body must be one {@link WRITE_RULES} allows. Anything else is
 *   refused before `fetch`, with a `validation_error`.
 * - goes to `https://<host>/api/v2`, where the host is the instance's, from
 *   {@link LAUNCHDARKLY_HOSTS} only.
 * - sends `LD-API-Version: {@link LD_API_VERSION}`.
 * - gives up after {@link LAUNCHDARKLY_TIMEOUT_MS}, its body included.
 * - follows no redirect, since the call carries the token: a 3xx is a
 *   failed status, and its body isn't read.
 * - reads at most {@link MAX_ANSWER_BYTES} of a 2xx, and
 *   {@link MAX_ERROR_BYTES} of an error, for LaunchDarkly's `code` and, on a
 *   write, its `message`.
 *
 * A call that gets no answer, or one LaunchDarkly wouldn't give, is logged
 * as a warning. A status outside 2xx is logged at debug only: the caller
 * decides what it means, and the route logs what reaches P0. A log line
 * names the call by its route, never by its URL, since
 * `GET /members?filter=email:` holds an email.
 */
export const newLaunchDarklyApi = ({
  instance,
  token,
  logger,
}: {
  instance: Instance;
  token: string;
  logger: Logger;
}): LaunchDarklyApi => {
  const host: string | undefined = Object.prototype.hasOwnProperty.call(
    LAUNCHDARKLY_HOSTS,
    instance
  )
    ? LAUNCHDARKLY_HOSTS[instance]
    : undefined;
  if (host === undefined) {
    // The account schema refuses this already.
    throw new ConnectorError({
      message:
        "The connector calls LaunchDarkly's commercial, EU and federal instances only.",
      payload: {},
      type: "validation_error",
    });
  }
  const origin = `https://${host}`;

  const unexpected = (
    call: LaunchDarklyCall,
    reason: UnexpectedAnswer,
    fields: Record<string, unknown> = {}
  ) => {
    logger.warn(
      { method: call.method, reason, route: call.route, ...fields },
      "LaunchDarkly's answer isn't one LaunchDarkly gives"
    );
    return new LaunchDarklyError(call, { kind: "unexpected", reason });
  };

  /** A call outside the allowlist, refused before it is made. */
  const refused = (
    call: LaunchDarklyCall,
    what: string,
    fields: Record<string, unknown> = {}
  ) => {
    logger.warn(
      { method: call.method, route: call.route, ...fields },
      "refused a LaunchDarkly call outside the connector's allowlist"
    );
    return new ConnectorError({
      message: `The connector refused to send LaunchDarkly ${call.method} ${call.route}: ${what}. Contact P0 support.`,
      payload: { method: call.method, route: call.route },
      type: "validation_error",
    });
  };

  /** The route's path below {@link LAUNCHDARKLY_API}, each value encoded. */
  const pathOf = (
    call: LaunchDarklyCall,
    params: Readonly<Record<string, string>> | undefined
  ) =>
    call.route
      .slice(LAUNCHDARKLY_API.length)
      .replace(/\{([A-Za-z]+)\}/g, (_match, name: string) => {
        const value = params?.[name];
        if (value === undefined) {
          throw refused(call, `it has no value for {${name}}`);
        }
        return segment(value);
      });

  /**
   * `fetch` throws a bare "fetch failed" and keeps what happened in `cause`.
   * A body that breaks off throws what broke it. Either is described, never
   * kept: both can quote the request.
   */
  const unreachable = (call: LaunchDarklyCall, error: unknown) => {
    const cause: unknown =
      error instanceof Error && error.cause !== undefined ? error.cause : error;
    const { code, name } = failureFacts(cause);
    const failure: LaunchDarklyFailure = {
      kind: "unreachable",
      timedOut: error instanceof Error && error.name === "TimeoutError",
      ...(code === undefined ? {} : { code }),
      ...(name === undefined ? {} : { name }),
    };
    logger.warn(
      { method: call.method, route: call.route, ...failure },
      "LaunchDarkly call got no answer"
    );
    return new LaunchDarklyError(call, failure);
  };

  /**
   * LaunchDarkly's `code` and, when `keepMessage`, its `message`, from an
   * error answer. An answer that breaks off, runs over the cap or isn't
   * LaunchDarkly's error body gives what it has, which may be nothing.
   */
  const readErrorBody = async (
    response: Response,
    keepMessage: boolean
  ): Promise<ErrorDetails> => {
    const text = await readBounded(response, MAX_ERROR_BYTES).catch(
      () => undefined
    );
    if (text === undefined) return {};
    const parsed = errorBody.safeParse(parseJson(text));
    if (!parsed.success) return {};
    const { code, message } = parsed.data;
    const quoted =
      keepMessage && message !== undefined ? quotable(message) : undefined;
    return {
      ...(code === undefined ? {} : { code }),
      ...(quoted === undefined ? {} : { message: quoted }),
    };
  };

  /**
   * Makes the call, and returns the 2xx answer's body as text, or
   * `undefined` when it is over the cap.
   */
  const exchange = async ({
    call,
    path,
    query,
    body,
  }: {
    call: LaunchDarklyCall;
    path: string;
    query?: Readonly<Record<string, string>>;
    body?: { json: unknown; contentType: string };
  }): Promise<string | undefined> => {
    const { method, route } = call;
    const search =
      query !== undefined && Object.keys(query).length > 0
        ? `?${new URLSearchParams(query).toString()}`
        : "";

    const fail = (error: unknown): never => {
      throw unreachable(call, error);
    };

    const response = await fetch(
      `${origin}${LAUNCHDARKLY_API}${path}${search}`,
      {
        headers: {
          Accept: "application/json",
          Authorization: token,
          "LD-API-Version": LD_API_VERSION,
          ...(body === undefined ? {} : { "Content-Type": body.contentType }),
        },
        method,
        ...(body === undefined ? {} : { body: JSON.stringify(body.json) }),
        redirect: "manual",
        signal: AbortSignal.timeout(LAUNCHDARKLY_TIMEOUT_MS),
      }
    ).catch(fail);

    const { status } = response;
    if (status >= 200 && status < 300) {
      const text = await readBounded(response, MAX_ANSWER_BYTES).catch(fail);
      logger.debug({ method, route, status }, "LaunchDarkly call succeeded");
      return text;
    }

    if (status < 400) await response.body?.cancel().catch(() => undefined);
    const details: ErrorDetails =
      status >= 400 ? await readErrorBody(response, method !== "GET") : {};
    const retryAfter =
      status === 429
        ? retryAfterSeconds(response.headers, Date.now())
        : undefined;
    const { code } = details;
    logger.debug(
      {
        method,
        route,
        status,
        ...(code === undefined ? {} : { code }),
        ...(retryAfter === undefined ? {} : { retryAfter }),
      },
      "LaunchDarkly call answered"
    );
    throw new LaunchDarklyError(call, {
      kind: "status",
      status,
      ...details,
      ...(retryAfter === undefined ? {} : { retryAfter }),
    });
  };

  /** The 2xx answer's text, parsed as `answer`. */
  const parse = <T>(
    call: LaunchDarklyCall,
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

  /** The route `name` names, when it is one of the allowlist's of `kind`. */
  const routeOf = (name: string, kind: "read" | "write"): LaunchDarklyCall => {
    const call = isRouteName(name) ? LAUNCHDARKLY_ROUTES[name] : undefined;
    if (call === undefined || (call.method === "GET") !== (kind === "read")) {
      throw new ConnectorError({
        message: `The connector refused to send a LaunchDarkly ${kind} outside its allowlist. Contact P0 support.`,
        payload: {},
        type: "validation_error",
      });
    }
    return call;
  };

  return {
    host,

    read: async ({ route: name, query = {}, answer, params }) => {
      const call = routeOf(name, "read");
      const path = pathOf(call, params);
      if (name === "getMembers" && !MEMBER_FILTER.test(query.filter ?? "")) {
        throw refused(call, "it looks members up by one email filter only");
      }
      const text = await exchange({ call, path, query });
      return parse(call, text, answer);
    },

    unexpected: (call, reason) => unexpected(call, reason),

    write: async ({ route: name, body, answer, params }) => {
      const call = routeOf(name, "write");
      const path = pathOf(call, params);
      const rule: { body: z.ZodType; contentType: string } = WRITE_RULES[name];
      const parsed = rule.body.safeParse(body);
      if (!parsed.success) {
        throw refused(call, "its body isn't one the connector sends", {
          issues: issuesOf(parsed.error),
        });
      }
      const text = await exchange({
        body: { contentType: rule.contentType, json: parsed.data },
        call,
        path,
      });
      return parse(call, text, answer);
    },
  };
};
