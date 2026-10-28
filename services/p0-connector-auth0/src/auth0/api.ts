import { ConnectorError, type Logger } from "@p0security/connector";
import { compact } from "lodash-es";
import { z } from "zod";

import { TENANT_PATTERN } from "../credentials.ts";

const API_TIMEOUT = 10_000;

export type Method = "DELETE" | "GET" | "PATCH" | "POST";

/**
 * An Auth0 call that failed.
 *
 * The request is never attached: its headers hold the access token, and the
 * token exchange's body holds the client secret.
 */
export class Auth0Error extends Error {
  /** The HTTP status, or `undefined` when Auth0 didn't answer. */
  readonly status: number | undefined;
  /** Auth0's own messages, from the body's `message` and `error_description`. */
  readonly auth0Messages: string[];
  /** Auth0's machine-readable code, such as `invalid_body` or `access_denied`. */
  readonly errorCode: string | undefined;
  /** On a 429, how many seconds to wait before trying again. */
  readonly retryAfter: string | undefined;

  constructor(params: {
    method: Method;
    path: string;
    status: number | undefined;
    auth0Messages: string[];
    errorCode?: string;
    retryAfter?: string;
  }) {
    const { method, path, status, auth0Messages } = params;
    super(
      `Auth0 ${method} ${path} failed${status === undefined ? "" : ` (${status})`}: ${
        auth0Messages[0] ?? "no message"
      }`
    );
    this.name = "Auth0Error";
    this.status = status;
    this.auth0Messages = auth0Messages;
    this.errorCode = params.errorCode;
    this.retryAfter = params.retryAfter;
  }
}

// The Management API's error bodies are `{ statusCode, error, message,
// errorCode }`. The token endpoint's are `{ error, error_description }`, where
// `error` is the code.
const errorBody = z.object({
  error: z.string().nullish(),
  message: z.string().nullish(),
  error_description: z.string().nullish(),
  errorCode: z.string().nullish(),
});

// Auth0's codes, such as `invalid_body` or `access_denied`.
const ERROR_CODE = /^[a-z][a-z0-9_.-]{0,63}$/;

const readError = (
  data: unknown
): { messages: string[]; errorCode: string | undefined } => {
  const parsed = errorBody.safeParse(data);
  if (!parsed.success) return { messages: [], errorCode: undefined };
  const { error, message, error_description, errorCode } = parsed.data;
  // Only the token endpoint's `error` is a code. The Management API's is the
  // HTTP reason, such as "Bad Request".
  const code = errorCode ?? (error_description ? error : undefined);
  return {
    messages: compact([message, error_description]),
    // A code is a short identifier. Anything else isn't taken as one, so it
    // can't carry what the request sent into the error P0 gets.
    errorCode: code && ERROR_CODE.test(code) ? code : undefined,
  };
};

const REDACTED = "[redacted]";

/**
 * Cuts each of `secrets` out of `messages`. A refusal's text is quoted to the
 * requestor, and nothing promises Auth0 never quotes a request back. `fetch`
 * does: its error for a header value it won't send quotes the whole
 * `Authorization` header.
 */
const withoutSecrets = (
  messages: string[],
  secrets: readonly string[]
): string[] =>
  messages.map((message) =>
    secrets
      .filter((secret) => secret !== "")
      // `split`/`join` rather than `replaceAll`: P0's backend type-checks this
      // file against an ES2017 lib through the connector's router type.
      .reduce(
        (text, secret) =>
          text
            .split(`Bearer ${secret}`)
            .join(REDACTED)
            .split(secret)
            .join(REDACTED),
        message
      )
  );

// How many causes under an error the log follows.
const MAX_CAUSES = 4;

/** The error and each cause under it, outermost first. */
const withCauses = (error: unknown, depth = 0): unknown[] =>
  error instanceof Error && error.cause !== undefined && depth < MAX_CAUSES
    ? [error, ...withCauses(error.cause, depth + 1)]
    : [error];

/**
 * Why a request got no answer, for the log: the error and its causes, where
 * `fetch` keeps the network's own reason, as text with the secrets cut out.
 * The error itself is never logged, because its message, and the stack that
 * repeats it, can hold the access token.
 */
const failureOf = (error: unknown, secrets: readonly string[]): string[] =>
  withoutSecrets(withCauses(error).map(String), secrets);

const readBody = async (response: Response): Promise<unknown> => {
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

/**
 * How long to wait after a 429, in seconds: `Retry-After` when Auth0 sends
 * it, which it does only for custom rate-limit policies, or else the time
 * until `x-ratelimit-reset`, a UNIX time in seconds.
 */
const retryAfterOf = (headers: Headers): string | undefined => {
  const retryAfter = headers.get("retry-after");
  if (retryAfter !== null) return retryAfter;
  const reset = Number(headers.get("x-ratelimit-reset") ?? NaN);
  if (!Number.isFinite(reset)) return undefined;
  return String(Math.max(0, Math.ceil(reset - Date.now() / 1000)));
};

/**
 * Refuses a tenant that isn't a canonical Auth0 domain before it becomes a
 * URL's host. The request schemas already refuse one. This check stops a
 * call that skipped them from reaching another host.
 */
const hostOf = (tenant: string): string => {
  if (!TENANT_PATTERN.test(tenant)) {
    throw new ConnectorError({
      type: "validation_error",
      message: `"${tenant}" isn't a canonical Auth0 tenant domain, such as acme.us.auth0.com.`,
      payload: { tenant },
    });
  }
  return tenant;
};

export type Auth0Request = {
  log: Logger;
  tenant: string;
  method: Method;
  /** The path, with every segment and query value already encoded. */
  path: string;
  /** The access token, on every call but the token exchange. */
  accessToken?: string;
  body?: unknown;
  /** What the request carries that must never be quoted back: the client secret. */
  secrets?: readonly string[];
};

// Auth0's free and developer tenants allow about 10 requests a second. A 429
// is retried after a fixed wait, a few times, and then goes back to P0 as
// `rate_limited`. Retrying a write is safe: Auth0 doesn't act on a request it
// answers with a 429.
/** How a 429 is retried. Tests shorten the wait. */
export const rateLimitRetry = { retries: 3, waitMs: 10_000 };

const isRateLimited = (error: unknown): boolean =>
  error instanceof Auth0Error && error.status === 429;

/** One call to the tenant, retried after a 429 as {@link rateLimitRetry} says. */
export const auth0Request = async (request: Auth0Request): Promise<unknown> => {
  for (let attempt = 1; ; attempt++) {
    try {
      return await sendOnce(request);
    } catch (error) {
      if (!isRateLimited(error) || attempt > rateLimitRetry.retries)
        throw error;
      const { log, method, path } = request;
      log.info(
        { method, path, attempt },
        "Auth0 rate limited the request, retrying"
      );
      await new Promise((resolve) =>
        setTimeout(resolve, rateLimitRetry.waitMs)
      );
    }
  }
};

const sendOnce = async ({
  log,
  tenant,
  method,
  path,
  accessToken,
  body,
  secrets: carried = [],
}: Auth0Request): Promise<unknown> => {
  const url = `https://${hostOf(tenant)}${path}`;
  const secrets = compact([...carried, accessToken]);
  let response: Response;
  let data: unknown;
  try {
    response = await fetch(url, {
      method,
      headers: {
        Accept: "application/json",
        ...(accessToken !== undefined
          ? { Authorization: `Bearer ${accessToken}` }
          : {}),
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      // Every URL is one the connector built. A redirect would resend the
      // body, which can hold the client secret, somewhere else.
      redirect: "error",
      signal: AbortSignal.timeout(API_TIMEOUT),
    });
    // Inside the `try`: the connection can still drop while the body arrives.
    data = await readBody(response);
  } catch (error) {
    log.error(
      { method, path, failure: failureOf(error, secrets) },
      "Auth0 request failed"
    );
    throw new Auth0Error({
      method,
      path,
      status: undefined,
      auth0Messages: withoutSecrets(
        [error instanceof Error ? error.message : String(error)],
        secrets
      ),
    });
  }

  if (!response.ok) {
    const { messages, errorCode } = readError(data);
    const error = new Auth0Error({
      method,
      path,
      status: response.status,
      auth0Messages: withoutSecrets(messages, secrets),
      errorCode,
      retryAfter:
        response.status === 429 ? retryAfterOf(response.headers) : undefined,
    });
    log.warn(
      {
        method,
        path,
        status: error.status,
        auth0Messages: error.auth0Messages,
        errorCode: error.errorCode,
        retryAfter: error.retryAfter,
      },
      "Auth0 request returned a non-2xx response"
    );
    throw error;
  }

  log.debug(
    { method, path, status: response.status },
    "Auth0 request succeeded"
  );
  return data;
};

/**
 * Reads a response body with `schema`, or fails as `unknown`: Auth0 answered
 * in a shape the connector doesn't know, which nobody can fix.
 */
export const parseResponse = <T>(params: {
  log: Logger;
  schema: z.ZodType<T>;
  data: unknown;
  what: string;
}): T => {
  const { log, schema, data, what } = params;
  const parsed = schema.safeParse(data);
  if (parsed.success) return parsed.data;
  log.warn(
    {
      what,
      // Where each issue is and its code, never a value: one body is a token.
      issues: parsed.error.issues.map(({ path, code }) => ({
        path: path.join("."),
        code,
      })),
    },
    "Auth0 returned a response the connector can't read"
  );
  throw new ConnectorError({
    type: "unknown",
    message: `Auth0 returned ${what} in a shape the connector doesn't recognize.`,
    payload: { what },
  });
};

/**
 * One URL path segment. `encodeURIComponent` leaves `.` and `..` alone, and
 * `fetch` would resolve them away, so they're refused here.
 */
export const segment = (value: string): string => {
  if (value === "" || value === "." || value === "..") {
    throw new ConnectorError({
      type: "validation_error",
      message: `"${value}" isn't a valid Auth0 id.`,
      payload: { segment: value },
    });
  }
  return encodeURIComponent(value);
};

// An access token is base64 text and dots. Nothing else is taken as one: a
// line break, say, isn't legal in a header, and `fetch` would refuse to send
// it with an error that quotes the whole `Authorization` header.
const tokenResponse = z.object({
  access_token: z.string().regex(/^[A-Za-z0-9_.+/=-]+$/),
  scope: z.string().optional(),
  expires_in: z.number().positive().optional(),
});

export type TokenGrant = {
  accessToken: string;
  /** The scopes granted, space-separated, when the response says. */
  scope: string | undefined;
  /** The token's lifetime in seconds, when the response says. */
  expiresIn: number | undefined;
};

/** The Management API's audience on a tenant. Always the canonical domain. */
export const managementAudience = (tenant: string): string =>
  `https://${tenant}/api/v2/`;

/**
 * `POST /oauth/token`: the client-credentials exchange, for a token whose
 * audience is the tenant's Management API.
 */
export const exchangeClientCredentials = async ({
  log,
  tenant,
  clientId,
  clientSecret,
}: {
  log: Logger;
  tenant: string;
  clientId: string;
  clientSecret: string;
}): Promise<TokenGrant> => {
  const data = await auth0Request({
    log,
    tenant,
    method: "POST",
    path: "/oauth/token",
    body: {
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret,
      audience: managementAudience(tenant),
    },
    secrets: [clientSecret],
  });
  const { access_token, scope, expires_in } = parseResponse({
    log,
    schema: tokenResponse,
    data,
    what: "the token exchange's response",
  });
  return { accessToken: access_token, scope, expiresIn: expires_in };
};

/** What every Management API call carries: the access token, and the tenant it's for. */
export type TenantCall = { log: Logger; tenant: string; accessToken: string };
