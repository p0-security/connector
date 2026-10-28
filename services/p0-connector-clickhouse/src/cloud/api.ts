import { ConnectorError, type Logger } from "@p0security/connector-core";
import { z } from "zod";

import type { ApiKey } from "../api-key.ts";
import { CLOUD_ID_PATTERN } from "../credentials.ts";

/** The Cloud API's one host. The connector calls no other for the Cloud API. */
export const CLOUD_HOST = "api.clickhouse.cloud";

/** How long a Cloud API call may take before it's abandoned, in milliseconds. */
export const CLOUD_TIMEOUT = 10_000;

export type Method = "DELETE" | "GET" | "PATCH" | "POST" | "PUT";

/** Which of ClickHouse Cloud's two APIs a call went to. */
export type Api = "cloud" | "query";

/**
 * A ClickHouse Cloud call that failed: to the Cloud API, or to one of P0's
 * Query API endpoints.
 *
 * The request is never attached: its `Authorization` header holds the key.
 */
export class ClickHouseError extends Error {
  readonly api: Api;
  readonly method: Method;
  /** The HTTP status, or `undefined` when ClickHouse Cloud didn't answer. */
  readonly status: number | undefined;
  /** ClickHouse Cloud's own messages, with the key cut out. */
  readonly messages: string[];
  /** On a 429, how many seconds to wait before trying again. */
  readonly retryAfter: string | undefined;

  constructor(params: {
    api: Api;
    method: Method;
    path: string;
    status: number | undefined;
    messages: string[];
    retryAfter?: string;
  }) {
    const { api, method, path, status, messages } = params;
    super(
      `ClickHouse Cloud ${api === "cloud" ? "API" : "Query API"} ${method} ${path} failed${
        status === undefined ? "" : ` (${status})`
      }: ${messages[0] ?? "no message"}`
    );
    this.name = "ClickHouseError";
    this.api = api;
    this.method = method;
    this.status = status;
    this.messages = messages;
    this.retryAfter = params.retryAfter;
  }
}

/** Basic auth's credentials for the key: `base64(keyId:keySecret)`. */
export const basicCredentials = ({ keyId, keySecret }: ApiKey): string =>
  Buffer.from(`${keyId}:${keySecret}`, "utf8").toString("base64");

/**
 * What a request with the key carries that must never be quoted back: the
 * whole `Authorization` value, the base64 credentials in it, and the key
 * secret itself. The key ID isn't a secret.
 */
export const secretsOf = (key: ApiKey): string[] => {
  const credentials = basicCredentials(key);
  return [`Basic ${credentials}`, credentials, key.keySecret];
};

const REDACTED = "[redacted]";

// Any Basic credential, the key's or not. A plain `/basic/i` would also catch
// the "Basic Service API Reader" role the messages name.
const BASIC_CREDENTIAL = /Basic [A-Za-z0-9+/=]{8,}/g;

/**
 * Cuts each of `secrets`, and anything shaped like a Basic credential, out of
 * `messages`. A failure's text reaches P0, and nothing promises ClickHouse
 * Cloud never quotes a request back. `fetch` does: its error for a header
 * value it won't send quotes the whole `Authorization` header.
 */
export const withoutSecrets = (
  messages: string[],
  secrets: readonly string[]
): string[] =>
  messages.map((message) =>
    secrets
      .filter((secret) => secret !== "")
      // `split`/`join` rather than `replaceAll`: P0's backend type-checks this
      // file against an ES2017 lib through the connector's router type.
      .reduce((text, secret) => text.split(secret).join(REDACTED), message)
      .replace(BASIC_CREDENTIAL, REDACTED)
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
 * repeats it, can hold the key.
 */
export const failureOf = (
  error: unknown,
  secrets: readonly string[]
): string[] => withoutSecrets(withCauses(error).map(String), secrets);

/** The body as JSON, or as text when it isn't JSON, or `undefined` when empty. */
export const readBody = async (response: Response): Promise<unknown> => {
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

// The longest message from ClickHouse Cloud the connector passes on.
const MAX_MESSAGE_LENGTH = 500;

// Every documented error body is `{ status, error, requestId }`.
const errorBody = z.object({ error: z.string() });

/**
 * ClickHouse Cloud's message in an error body, if it has one, with each of
 * `secrets` cut out before it's cut short: shortened first, a secret that
 * crossed the cut would keep its first part.
 */
export const readError = (
  data: unknown,
  secrets: readonly string[]
): string[] => {
  const shortened = (message: string) =>
    withoutSecrets([message], secrets).map((text) =>
      text.slice(0, MAX_MESSAGE_LENGTH)
    );
  const parsed = errorBody.safeParse(data);
  if (parsed.success) return shortened(parsed.data.error);
  // The Query API answers a SQL failure as text, such as
  // `Code: 497. DB::Exception: ...`.
  if (typeof data === "string" && data.trim() !== "") {
    return shortened(data.trim());
  }
  return [];
};

/** How long to wait after a 429, in seconds, when ClickHouse Cloud says. */
export const retryAfterOf = (headers: Headers): string | undefined =>
  headers.get("retry-after") ?? undefined;

const ID = CLOUD_ID_PATTERN.source.slice(1, -1);
const ORGANIZATION = `/v1/organizations/${ID}`;
const SERVICE = `${ORGANIZATION}/services/${ID}`;
const ENDPOINTS = `${SERVICE}/query-api-endpoints`;
const ROLES = `${ORGANIZATION}/roles`;

/**
 * Every Cloud API call the connector makes, and nothing else. A call outside
 * this list is refused before it is sent.
 */
const ALLOWED: readonly (readonly [Method, string])[] = [
  ["GET", ORGANIZATION],
  ["GET", `${ORGANIZATION}/members`],
  ["GET", `${ORGANIZATION}/keys`],
  ["GET", `${ORGANIZATION}/services`],
  ["GET", SERVICE],
  ["GET", ENDPOINTS],
  ["POST", ENDPOINTS],
  ["GET", `${ENDPOINTS}/${ID}`],
  ["PUT", `${ENDPOINTS}/${ID}`],
  ["DELETE", `${ENDPOINTS}/${ID}`],
  ["GET", ROLES],
  ["POST", ROLES],
  ["PATCH", `${ROLES}/${ID}`],
  ["DELETE", `${ROLES}/${ID}`],
];

const ALLOWED_PATTERNS = ALLOWED.map(
  ([method, path]) => [method, new RegExp(`^${path}$`)] as const
);

/** Whether the connector may make this Cloud API call. */
export const isAllowed = (method: Method, path: string): boolean =>
  ALLOWED_PATTERNS.some(
    ([allowed, pattern]) => allowed === method && pattern.test(path)
  );

/**
 * One URL path segment: a Cloud ID. Anything else is refused before it
 * becomes part of a path.
 */
export const segment = (value: string): string => {
  if (!CLOUD_ID_PATTERN.test(value)) {
    throw new ConnectorError({
      type: "validation_error",
      // The value isn't quoted: it could be anything, a key included.
      message:
        "The connector was given an ID that isn't a ClickHouse Cloud ID.",
      payload: {},
    });
  }
  return value;
};

export type CloudRequest = {
  log: Logger;
  key: ApiKey;
  method: Method;
  /** The path, built from {@link segment}s. */
  path: string;
  /** Query parameters, such as a page's cursor. */
  search?: Record<string, string>;
  body?: unknown;
};

/**
 * One Cloud API call, with Basic auth, to {@link CLOUD_HOST} only, and only
 * one of the {@link ALLOWED} calls. Returns the parsed body.
 */
export const cloudRequest = async ({
  log,
  key,
  method,
  path,
  search,
  body,
}: CloudRequest): Promise<unknown> => {
  if (!isAllowed(method, path)) {
    throw new ConnectorError({
      type: "validation_error",
      message: `The connector doesn't make the ClickHouse Cloud API call ${method} ${path}.`,
      payload: { method },
    });
  }
  const params = new URLSearchParams(search).toString();
  const query = params === "" ? "" : `?${params}`;
  const url = `https://${CLOUD_HOST}${path}${query}`;
  const secrets = secretsOf(key);
  const noAnswer = (error: unknown): never => {
    log.warn(
      { method, path, failure: failureOf(error, secrets) },
      "ClickHouse Cloud API request failed"
    );
    throw new ClickHouseError({
      api: "cloud",
      method,
      path,
      status: undefined,
      messages: withoutSecrets(
        [error instanceof Error ? error.message : String(error)],
        secrets
      ),
    });
  };
  const response = await fetch(url, {
    method,
    headers: {
      Accept: "application/json",
      Authorization: `Basic ${basicCredentials(key)}`,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    // Every URL is one the connector built. A redirect would resend the
    // key somewhere else.
    redirect: "error",
    signal: AbortSignal.timeout(CLOUD_TIMEOUT),
  }).catch(noAnswer);
  // The connection can still drop while the body arrives.
  const data = await readBody(response).catch(noAnswer);

  if (!response.ok) {
    const error = new ClickHouseError({
      api: "cloud",
      method,
      path,
      status: response.status,
      messages: readError(data, secrets),
      retryAfter:
        response.status === 429 ? retryAfterOf(response.headers) : undefined,
    });
    log.warn(
      {
        method,
        path,
        status: error.status,
        messages: error.messages,
        retryAfter: error.retryAfter,
      },
      "ClickHouse Cloud API request returned a non-2xx response"
    );
    throw error;
  }

  log.debug(
    { method, path, status: response.status },
    "ClickHouse Cloud API request succeeded"
  );
  return data;
};

/**
 * Reads a response body with `schema`, or fails as `unknown`: ClickHouse
 * Cloud answered in a shape the connector doesn't know, which nobody can fix.
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
      // Where each issue is and its code, never a value.
      issues: parsed.error.issues.map(({ path, code }) => ({
        path: path.join("."),
        code,
      })),
    },
    "ClickHouse Cloud returned a response the connector can't read"
  );
  throw new ConnectorError({
    type: "unknown",
    message: `ClickHouse Cloud returned ${what} in a shape P0 doesn't recognize.`,
    payload: { what },
  });
};
