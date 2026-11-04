import type { Logger } from "@p0security/connector-core";
import { z } from "zod";

import { failureFacts } from "../failure.ts";

/**
 * Cloudflare's API. The connector calls no other host, so the install token
 * can't be sent anywhere else.
 */
export const CLOUDFLARE_API = "https://api.cloudflare.com/client/v4";

/** How long Cloudflare has to answer a call, its body included. */
export const CLOUDFLARE_TIMEOUT_MS = 10_000;

/** The most of a 2xx answer the connector reads. */
export const MAX_ANSWER_BYTES = 4 * 1024 * 1024;

/** The most of an error answer the connector reads. */
export const MAX_ERROR_BYTES = 16 * 1024;

/** Items per page of a paged list: the most `GET /zones` takes. */
export const PAGE_SIZE = 50;

/** The most pages of a list the connector reads before giving up. */
export const MAX_PAGES = 100;

type Method = "DELETE" | "GET" | "POST" | "PUT";

/**
 * What a call is, for its messages and its log lines. `route` is the path
 * as Cloudflare's API reference writes it, with `{name}` for each id, so
 * neither carries an id.
 */
export type CloudflareCall = { method: Method; route: `/${string}` };

/** Every call the connector may make, and nothing else. */
export const CLOUDFLARE_ROUTES = {
  createToken: { method: "POST", route: "/accounts/{account_id}/tokens" },
  deleteToken: {
    method: "DELETE",
    route: "/accounts/{account_id}/tokens/{token_id}",
  },
  getToken: {
    method: "GET",
    route: "/accounts/{account_id}/tokens/{token_id}",
  },
  listPermissionGroups: {
    method: "GET",
    route: "/accounts/{account_id}/tokens/permission_groups",
  },
  listTokens: { method: "GET", route: "/accounts/{account_id}/tokens" },
  listZones: { method: "GET", route: "/zones" },
  updateToken: {
    method: "PUT",
    route: "/accounts/{account_id}/tokens/{token_id}",
  },
  verifyToken: {
    method: "GET",
    route: "/accounts/{account_id}/tokens/verify",
  },
} as const satisfies Record<string, CloudflareCall>;

export type RouteName = keyof typeof CLOUDFLARE_ROUTES;

/** Why an answer isn't one Cloudflare gives. `endless` is the pager's. */
export type UnexpectedAnswer =
  "endless" | "not_json" | "too_large" | "wrong_shape";

/** How a call failed. */
export type CloudflareFailure =
  /** An answer outside 2xx, or a 2xx with `success: false`. */
  | {
      kind: "status";
      status: number;
      /** Cloudflare's codes from `errors`, which carry no request data. */
      codes: number[];
      /** An error message names a limit, such as the token cap. */
      limitReached: boolean;
    }
  /** No answer: `code` and `name` are Node's, and say what happened. */
  | {
      kind: "unreachable";
      timedOut: boolean;
      code?: number | string;
      name?: string;
    }
  /** A 2xx with a body Cloudflare wouldn't send. */
  | { kind: "unexpected"; reason: UnexpectedAnswer };

/**
 * A Cloudflare call that failed.
 *
 * It holds the call's template and how it failed, and nothing of the
 * request: not the URL, and not the headers, which carry the token. Nor a
 * `cause`: `fetch`'s errors can quote the request.
 */
export class CloudflareError extends Error {
  constructor(
    readonly call: CloudflareCall,
    readonly failure: CloudflareFailure
  ) {
    super(`Cloudflare ${call.method} ${call.route}: ${failure.kind}`);
    this.name = "CloudflareError";
  }
}

/**
 * The answer's body as text, or `undefined` when it is longer than `cap`
 * bytes. A copy of the Miro (AI) connector's `readBounded`.
 */
const readBounded = async (
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

const parseJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

// Cloudflare's v4 envelope, as much of it as the connector reads.
const errorEnvelope = z.object({
  success: z.boolean().optional(),
  errors: z
    .array(z.object({ code: z.number().optional(), message: z.string() }))
    .optional()
    .catch(undefined),
});

const resultInfo = z.object({
  page: z.number().int(),
  total_pages: z.number().int().nonnegative(),
});

// A limit such as the 500-token cap. Cloudflare documents no code for the
// cap, so the message is matched (spec section 4).
const LIMIT_MESSAGE = /\b(limit|maximum|quota|exceed)/i;

/** Where a parse went wrong, never what it held. */
const issuesOf = ({ issues }: z.ZodError) =>
  issues.map(({ code, path }) => ({ code, path: path.map(String).join(".") }));

/** What a call takes, beside its route. */
type CallOptions = {
  /** The value of each `{name}` in the route. Each is encoded as a segment. */
  params?: Readonly<Record<string, string>>;
  query?: Readonly<Record<string, string>>;
  body?: unknown;
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

/** Cloudflare's API, as the install token. */
export type CloudflareApi = {
  /** One call, whose `result` must be `result`'s shape. */
  call: <T>(
    name: RouteName,
    result: z.ZodType<T>,
    options?: CallOptions
  ) => Promise<T>;
  /**
   * Every page of a list: `page` from 1, {@link PAGE_SIZE} to a page, until
   * `result_info.total_pages`.
   */
  list: <T>(
    name: RouteName,
    item: z.ZodType<T>,
    options?: Omit<CallOptions, "body">
  ) => Promise<T[]>;
};

/**
 * Makes Cloudflare calls with the install token, as
 * `Authorization: Bearer <token>`.
 *
 * The token lives only in this closure and in the header it sends: nothing
 * that holds it is returned, logged or thrown.
 *
 * Every call:
 * - is one of {@link CLOUDFLARE_ROUTES}, sent to {@link CLOUDFLARE_API}.
 * - gives up after {@link CLOUDFLARE_TIMEOUT_MS}, its body included.
 * - follows no redirect, since the call carries the token.
 * - is sent once. A 429 blocks every call for five minutes, so the
 *   connector doesn't wait for it: P0 decides.
 *
 * A log line names the call by its route, never by its URL.
 */
export const newCloudflareApi = ({
  token,
  logger,
}: {
  token: string;
  logger: Logger;
}): CloudflareApi => {
  const unexpected = (
    call: CloudflareCall,
    reason: UnexpectedAnswer,
    fields: Record<string, unknown> = {}
  ) => {
    logger.warn(
      { method: call.method, reason, route: call.route, ...fields },
      "Cloudflare's answer isn't one Cloudflare gives"
    );
    return new CloudflareError(call, { kind: "unexpected", reason });
  };

  const unreachable = (call: CloudflareCall, error: unknown) => {
    const cause: unknown =
      error instanceof Error && error.cause !== undefined ? error.cause : error;
    const { code, name } = failureFacts(cause);
    const failure: CloudflareFailure = {
      kind: "unreachable",
      timedOut: error instanceof Error && error.name === "TimeoutError",
      ...(code === undefined ? {} : { code }),
      ...(name === undefined ? {} : { name }),
    };
    logger.warn(
      { method: call.method, route: call.route, ...failure },
      "Cloudflare call got no answer"
    );
    return new CloudflareError(call, failure);
  };

  /** The status failure for an answer, from its envelope's `errors`. */
  const failed = (call: CloudflareCall, status: number, json: unknown) => {
    const errors = errorEnvelope.safeParse(json).data?.errors ?? [];
    const codes = errors.flatMap(({ code }) =>
      code === undefined ? [] : [code]
    );
    const limitReached = errors.some(({ message }) =>
      LIMIT_MESSAGE.test(message)
    );
    // Cloudflare's messages can echo the request, so only the codes are
    // logged.
    logger.debug(
      { codes, limitReached, method: call.method, route: call.route, status },
      "Cloudflare call failed"
    );
    return new CloudflareError(call, {
      codes,
      kind: "status",
      limitReached,
      status,
    });
  };

  /** One call: the envelope's parsed JSON. */
  const exchange = async (
    call: CloudflareCall,
    { params = {}, query = {}, body }: CallOptions
  ): Promise<unknown> => {
    const { method } = call;
    const search =
      Object.keys(query).length > 0
        ? `?${new URLSearchParams(query).toString()}`
        : "";
    const fail = (error: unknown): never => {
      throw unreachable(call, error);
    };

    const response = await fetch(
      `${CLOUDFLARE_API}${fillRoute(call.route, params)}${search}`,
      {
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        method,
        redirect: "manual",
        signal: AbortSignal.timeout(CLOUDFLARE_TIMEOUT_MS),
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      }
    ).catch(fail);

    const { status } = response;
    const ok = status >= 200 && status < 300;
    if (status < 400 && !ok) {
      await response.body?.cancel().catch(() => undefined);
      throw failed(call, status, undefined);
    }
    const text = await readBounded(
      response,
      ok ? MAX_ANSWER_BYTES : MAX_ERROR_BYTES
    ).catch(fail);
    const json = text === undefined ? undefined : parseJson(text);
    if (!ok) throw failed(call, status, json);
    if (text === undefined) throw unexpected(call, "too_large");
    if (json === undefined) throw unexpected(call, "not_json");
    if (errorEnvelope.safeParse(json).data?.success === false) {
      throw failed(call, status, json);
    }
    logger.debug(
      { method, route: call.route, status },
      "Cloudflare call succeeded"
    );
    return json;
  };

  const parse = <T>(
    call: CloudflareCall,
    json: unknown,
    shape: z.ZodType<T>
  ): T => {
    const parsed = shape.safeParse(json);
    if (!parsed.success) {
      throw unexpected(call, "wrong_shape", { issues: issuesOf(parsed.error) });
    }
    return parsed.data;
  };

  return {
    call: async (name, result, options = {}) => {
      const call = CLOUDFLARE_ROUTES[name];
      const json = await exchange(call, options);
      return parse(call, json, z.object({ result })).result;
    },

    list: async (name, item, { query = {}, ...options } = {}) => {
      const call = CLOUDFLARE_ROUTES[name];
      const page = z.object({ result: z.array(item), result_info: resultInfo });
      const items: z.infer<typeof item>[] = [];
      for (let number = 1; number <= MAX_PAGES; number++) {
        const json = await exchange(call, {
          ...options,
          query: {
            ...query,
            page: String(number),
            per_page: String(PAGE_SIZE),
          },
        });
        const { result, result_info } = parse(call, json, page);
        items.push(...result);
        if (number >= result_info.total_pages || result.length === 0) {
          return items;
        }
      }
      throw unexpected(call, "endless", { pages: MAX_PAGES });
    },
  };
};

/**
 * A resource key and what it grants: `"*"`, or the keys nested under it,
 * such as an account's zones (spec section 4).
 */
export type TokenResources = { [key: string]: TokenResources | "*" };

const tokenResources: z.ZodType<TokenResources> = z.lazy(() =>
  z.record(z.string(), z.union([z.literal("*"), tokenResources]))
);

const tokenPolicy = z.object({
  effect: z.enum(["allow", "deny"]),
  resources: tokenResources,
  permission_groups: z.array(
    z.object({ id: z.string(), name: z.string().optional() })
  ),
});

export type TokenPolicy = z.infer<typeof tokenPolicy>;

/** A policy as a mint or a `PUT` sends it: groups by `id` only. */
export type TokenPolicyInput = {
  effect: "allow";
  resources: TokenResources;
  permission_groups: { id: string }[];
};

const token = z.object({
  id: z.string().min(1),
  name: z.string(),
  status: z.string(),
  expires_on: z.string().optional(),
  policies: z.array(tokenPolicy),
});

export type CloudflareToken = z.infer<typeof token>;

// A list doesn't promise each token's policies, so it reads only these.
const listedToken = token.pick({
  expires_on: true,
  id: true,
  name: true,
  status: true,
});

export type ListedToken = z.infer<typeof listedToken>;

const verifiedToken = z.object({
  id: z.string().min(1),
  status: z.string(),
  expires_on: z.string().optional(),
});

const mintedToken = z.object({
  id: z.string().min(1),
  value: z.string().min(1),
});

const permissionGroup = z.object({
  id: z.string().min(1),
  name: z.string(),
  scopes: z.array(z.string()),
  is_selectable: z.boolean().optional(),
});

export type PermissionGroup = z.infer<typeof permissionGroup>;

const zone = z.object({ id: z.string().min(1), name: z.string().min(1) });

export type Zone = z.infer<typeof zone>;

/** What a mint or a `PUT` sets on a grant token. */
export type TokenSpec = {
  name: string;
  policies: TokenPolicyInput[];
  /** ISO 8601, in UTC. */
  expiresOn: string;
};

const tokenBody = ({ name, policies, expiresOn }: TokenSpec) => ({
  expires_on: expiresOn,
  name,
  policies,
});

/** The calls the connector makes on one account, as its install token. */
export const newCloudflareClient = (api: CloudflareApi, accountId: string) => {
  const account = { account_id: accountId };
  const ofToken = (tokenId: string) => ({ ...account, token_id: tokenId });

  return {
    /** The install token itself: its id and whether it is active. */
    verifyToken: () =>
      api.call("verifyToken", verifiedToken, { params: account }),

    getToken: (tokenId: string) =>
      api.call("getToken", token, { params: ofToken(tokenId) }),

    /** Every token on the account, all pages. */
    listTokens: () => api.list("listTokens", listedToken, { params: account }),

    /** Mints a token. `value` is the only copy of its secret. */
    createToken: (spec: TokenSpec) =>
      api.call("createToken", mintedToken, {
        body: tokenBody(spec),
        params: account,
      }),

    /** Replaces a token's name, policies and expiry. Its value doesn't change. */
    updateToken: (tokenId: string, spec: TokenSpec) =>
      api.call("updateToken", z.unknown(), {
        body: { ...tokenBody(spec), status: "active" },
        params: ofToken(tokenId),
      }),

    deleteToken: (tokenId: string) =>
      api.call("deleteToken", z.unknown(), { params: ofToken(tokenId) }),

    /** Every permission group the account has. Cloudflare doesn't page it. */
    listPermissionGroups: () =>
      api.call("listPermissionGroups", z.array(permissionGroup), {
        params: account,
      }),

    /** Every zone of the account, all pages. */
    listZones: () =>
      api.list("listZones", zone, { query: { "account.id": accountId } }),
  };
};

export type CloudflareClient = ReturnType<typeof newCloudflareClient>;
