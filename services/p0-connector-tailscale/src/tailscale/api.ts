import { ConnectorError, type Logger } from "@p0security/connector-core";
import { compact } from "lodash-es";
import { z } from "zod";

import { TAILNET_PATTERN } from "../credentials.ts";

/**
 * The one host the connector calls. Every URL is built on it, so a token
 * can't be sent anywhere else.
 */
export const API_ORIGIN = "https://api.tailscale.com";

export const API_TIMEOUT_MS = 10_000;

/** The most of Tailscale's own message a refusal quotes. */
const MAX_MESSAGE_LENGTH = 500;

export type Method = "DELETE" | "GET" | "PATCH" | "POST";

/**
 * A Tailscale call that failed.
 *
 * The request is never attached: its headers hold the access token, and a
 * token exchange's body holds the client secret or the identity token.
 */
export class TailscaleError extends Error {
  /** The HTTP status, or `undefined` when Tailscale didn't answer. */
  readonly status: number | undefined;
  /** Tailscale's own message, from the body's `message`, with secrets cut out. */
  readonly tailscaleMessage: string | undefined;
  /** On a 429, how many seconds to wait before trying again, when Tailscale says. */
  readonly retryAfter: string | undefined;
  /** The scope the call needs, such as `devices:core:read`. */
  readonly scope: string | undefined;
  /** The scopes of the token the call was sent with, when they're known (see {@link TailnetCall}). */
  readonly tokenScopes: readonly string[] | undefined;

  constructor(params: {
    method: Method;
    path: string;
    status: number | undefined;
    tailscaleMessage?: string;
    retryAfter?: string;
    scope?: string;
    tokenScopes?: readonly string[] | undefined;
  }) {
    const { method, path, status, tailscaleMessage } = params;
    super(
      `Tailscale ${method} ${path} failed${status === undefined ? "" : ` (${status})`}: ${
        tailscaleMessage ?? "no message"
      }`
    );
    this.name = "TailscaleError";
    this.status = status;
    this.tailscaleMessage = tailscaleMessage;
    this.retryAfter = params.retryAfter;
    this.scope = params.scope;
    this.tokenScopes = params.tokenScopes;
  }
}

// Tailscale's error bodies are `{ "message": "..." }`. The token endpoints
// answer OAuth's `{ error, error_description }`.
const errorBody = z.object({
  message: z.string().nullish(),
  error: z.string().nullish(),
  error_description: z.string().nullish(),
});

const messageOf = (data: unknown): string | undefined => {
  const parsed = errorBody.safeParse(data);
  if (!parsed.success) return undefined;
  const { message, error, error_description } = parsed.data;
  return message ?? error_description ?? error ?? undefined;
};

const REDACTED = "[redacted]";

/**
 * Cuts each of `secrets` out of `text`, and caps its length. A refusal's text
 * is quoted to the requestor, and nothing promises Tailscale never quotes a
 * request back. `fetch` does: its error for a header value it won't send
 * quotes the whole `Authorization` header.
 */
export const withoutSecrets = (
  text: string,
  secrets: readonly string[]
): string => {
  const cut = secrets
    .filter((secret) => secret !== "")
    // `split`/`join` rather than `replaceAll`: P0's backend type-checks this
    // file against an ES2017 lib through the connector's router type.
    .reduce(
      (out, secret) =>
        out
          .split(`Bearer ${secret}`)
          .join(REDACTED)
          .split(secret)
          .join(REDACTED),
      text
    );
  return cut.length > MAX_MESSAGE_LENGTH
    ? `${cut.slice(0, MAX_MESSAGE_LENGTH)}...`
    : cut;
};

// How many causes under an error the log follows.
const MAX_CAUSES = 4;

/** The error and each cause under it, outermost first. */
const withCauses = (error: unknown, depth = 0): unknown[] =>
  error instanceof Error && error.cause !== undefined && depth < MAX_CAUSES
    ? [error, ...withCauses(error.cause, depth + 1)]
    : [error];

/**
 * Why a request got no answer, for the log: the error and its causes as
 * text, with the secrets cut out. The error itself is never logged, because
 * its message, and the stack that repeats it, can hold the access token.
 */
const failureOf = (error: unknown, secrets: readonly string[]): string[] =>
  withCauses(error).map((each) => withoutSecrets(String(each), secrets));

const parseText = (text: string): unknown => {
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

/**
 * One URL path segment. `encodeURIComponent` leaves `.` and `..` alone, and
 * `fetch` would resolve them away, so they're refused here.
 */
export const segment = (value: string): string => {
  if (value === "" || value === "." || value === "..") {
    throw new ConnectorError({
      type: "validation_error",
      message: `"${value}" isn't a valid Tailscale id.`,
      payload: { segment: value },
    });
  }
  return encodeURIComponent(value);
};

/**
 * The tailnet's path segment. The request schemas already refuse anything
 * else; this stops a call that skipped them from reaching another path.
 */
export const tailnetSegment = (tailnet: string): string => {
  if (!TAILNET_PATTERN.test(tailnet)) {
    throw new ConnectorError({
      type: "validation_error",
      message: `"${tailnet}" isn't a Tailnet ID, such as T1234CNTRL.`,
      payload: { tailnet },
    });
  }
  return segment(tailnet);
};

/** What a request sends, if anything. */
export type RequestBody = { form: Record<string, string> } | { json: unknown };

export type TailscaleRequest = {
  log: Logger;
  method: Method;
  /** The path under the origin, with every segment and query value already encoded. */
  path: string;
  /** The access token, on every call but the token exchanges. */
  accessToken?: string;
  body?: RequestBody;
  /** What the request carries that must never be quoted back. */
  secrets?: readonly string[];
  /** The scope the call needs, which a failure carries. */
  scope?: string;
  /** The scopes the access token carries, when known, which a failure carries. */
  tokenScopes?: readonly string[] | undefined;
};

export type TailscaleResponse = {
  status: number;
  /** The body as text, as Tailscale sent it. */
  text: string;
  /** The body parsed as JSON, or the text when it isn't JSON. */
  data: unknown;
};

const contentTypeOf = (body: RequestBody): string =>
  "form" in body ? "application/x-www-form-urlencoded" : "application/json";

const bodyText = (body: RequestBody): string =>
  "form" in body
    ? new URLSearchParams(body.form).toString()
    : JSON.stringify(body.json);

/**
 * Sends the request and reads its body. A request that gets no answer
 * (a network failure, a timeout, a dropped connection) is logged at `warn`,
 * since it's the network or Tailscale and not the connector, and thrown as a
 * {@link TailscaleError} without a status.
 */
const send = async (
  { log, method, path, accessToken, body }: TailscaleRequest,
  secrets: readonly string[]
): Promise<{ response: Response; text: string }> => {
  try {
    const response = await fetch(`${API_ORIGIN}${path}`, {
      method,
      headers: {
        Accept: "application/json",
        ...(accessToken !== undefined
          ? { Authorization: `Bearer ${accessToken}` }
          : {}),
        ...(body !== undefined ? { "Content-Type": contentTypeOf(body) } : {}),
      },
      body: body !== undefined ? bodyText(body) : undefined,
      // Every URL is one the connector built. A redirect would resend the
      // body, which can hold a secret, somewhere else.
      redirect: "error",
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
    // Inside the `try`: the connection can still drop while the body arrives.
    return { response, text: await response.text() };
  } catch (error) {
    log.warn(
      { method, path, failure: failureOf(error, secrets) },
      "Tailscale request failed"
    );
    throw new TailscaleError({
      method,
      path,
      status: undefined,
      tailscaleMessage: withoutSecrets(
        error instanceof Error ? error.message : String(error),
        secrets
      ),
    });
  }
};

export const tailscaleRequest = async (
  request: TailscaleRequest
): Promise<TailscaleResponse> => {
  const {
    log,
    method,
    path,
    accessToken,
    secrets: carried = [],
    scope,
    tokenScopes,
  } = request;
  const secrets = compact([...carried, accessToken]);
  const { response, text } = await send(request, secrets);
  const data = parseText(text);
  if (!response.ok) {
    const message = messageOf(data);
    const error = new TailscaleError({
      method,
      path,
      status: response.status,
      tailscaleMessage:
        message === undefined ? undefined : withoutSecrets(message, secrets),
      retryAfter:
        response.status === 429
          ? (response.headers.get("retry-after") ?? undefined)
          : undefined,
      scope,
      tokenScopes,
    });
    log.warn(
      {
        method,
        path,
        status: error.status,
        tailscaleMessage: error.tailscaleMessage,
        retryAfter: error.retryAfter,
      },
      "Tailscale request returned a non-2xx response"
    );
    throw error;
  }

  log.debug(
    { method, path, status: response.status },
    "Tailscale request succeeded"
  );
  return { status: response.status, text, data };
};

/**
 * Reads a response body with `schema`, or fails as `unknown`: Tailscale
 * answered in a shape the connector doesn't know, which nobody can fix.
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
    "Tailscale returned a response the connector can't read"
  );
  throw new ConnectorError({
    type: "unknown",
    message: `Tailscale returned ${what} in a shape the connector doesn't recognize.`,
    payload: { what },
  });
};

// An access token is `tskey-` text. Nothing else is taken as one: a line
// break, say, isn't legal in a header, and `fetch` would refuse to send it
// with an error that quotes the whole `Authorization` header.
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

const grantOf = (log: Logger, data: unknown, what: string): TokenGrant => {
  const { access_token, scope, expires_in } = parseResponse({
    log,
    schema: tokenResponse,
    data,
    what,
  });
  return { accessToken: access_token, scope, expiresIn: expires_in };
};

/**
 * `POST /api/v2/oauth/token`: the client-credentials exchange, for a token
 * with `scopes`, which must be a subset of the OAuth client's, or with all of
 * the client's when `scopes` is empty.
 */
export const exchangeClientCredentials = async ({
  log,
  clientId,
  clientSecret,
  scopes,
}: {
  log: Logger;
  clientId: string;
  clientSecret: string;
  scopes: readonly string[];
}): Promise<TokenGrant> => {
  const { data } = await tailscaleRequest({
    log,
    method: "POST",
    path: "/api/v2/oauth/token",
    body: {
      form: {
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
        // Without one, the token carries every scope the client holds.
        ...(scopes.length > 0 ? { scope: scopes.join(" ") } : {}),
      },
    },
    secrets: [clientSecret],
  });
  return grantOf(log, data, "the token exchange's response");
};

/**
 * `POST /api/v2/oauth/token-exchange`: workload identity federation. Trades
 * the connector's own cloud identity token for a Tailscale token. It takes no
 * scope: the token carries every scope configured on the federated identity.
 */
export const exchangeIdentityToken = async ({
  log,
  clientId,
  jwt,
}: {
  log: Logger;
  clientId: string;
  jwt: string;
}): Promise<TokenGrant> => {
  const { data } = await tailscaleRequest({
    log,
    method: "POST",
    path: "/api/v2/oauth/token-exchange",
    body: { form: { client_id: clientId, jwt } },
    secrets: [jwt],
  });
  return grantOf(log, data, "the federated token exchange's response");
};

/** What every tailnet call carries: the access token, and the tailnet it's for. */
export type TailnetCall = {
  log: Logger;
  tailnet: string;
  accessToken: string;
  /**
   * The scopes the access token carries, when they're known. Tailscale
   * answers a call whose token lacks its scope with 404 "not found", as it
   * does a missing object, so a failure carries these to tell them apart.
   */
  tokenScopes?: readonly string[] | undefined;
};
