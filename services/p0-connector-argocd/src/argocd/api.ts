// copy of services/p0-connector-harbor/src/harbor/api.ts, with Argo CD's
// bearer token, its two route prefixes and its `**` path parts
import { ConnectorError, type Logger } from "@p0security/connector-core";
import type { z } from "zod";

import { describeFailure, failureFacts } from "../failure.ts";

/** How long Argo CD has to answer a call, its body included. */
export const ARGOCD_TIMEOUT_MS = 10_000;

/**
 * The most of an answer the connector reads. Its largest answers are an
 * Application and `argocd-rbac-cm`'s manifest, and Kubernetes keeps an object
 * to about 1.5 MiB, which JSON escaping can at most double in a manifest
 * string. The URL is whatever P0 sent, so what answers may send anything.
 */
export const MAX_ANSWER_BYTES = 4 * 1024 * 1024;

type Method = "GET" | "POST";

/**
 * A path on Argo CD's API. Almost every route is under `/api/v1`, but the
 * version isn't.
 */
export type ArgoCdPath = "/api/version" | `/api/v1/${string}`;

/**
 * What a call is, for its messages, its log lines and its 403.
 *
 * `route` is the path as Argo CD's API reference writes it, with
 * `{placeholders}` for the values, so neither a message nor a log line
 * carries an Application's name or an object.
 */
export type ArgoCdCall = {
  method: Method;
  route: ArgoCdPath;
  /**
   * The policy the call needs, as an `argocd-rbac-cm` line names it
   * (`applications, get`), so a 403 can say which one may be missing.
   * Absent for a call any authenticated caller may make.
   */
  permission?: string;
};

/** Why an answer wasn't one Argo CD gives. */
export type UnexpectedAnswer = "not_json" | "too_large" | "wrong_shape";

/** How a call failed. */
export type ArgoCdFailure =
  /** No answer: `code` and `name` are Node's, and say what happened. */
  | {
      kind: "unreachable";
      timedOut: boolean;
      code?: number | string;
      name?: string;
    }
  /**
   * Argo CD answered as it does a caller whose token it didn't accept:
   * `loggedIn: false`, from a route that answers anyone.
   */
  | { kind: "anonymous" }
  /**
   * The managing Application doesn't manage `argocd-rbac-cm` in
   * `namespace`: Argo CD's 400 on the Application's resource routes.
   */
  | { kind: "not_managed"; app: string; namespace: string }
  /** An answer outside 2xx. */
  | { kind: "status"; status: number }
  /** A 2xx with a body Argo CD wouldn't send. */
  | { kind: "unexpected"; reason: UnexpectedAnswer };

const describe = (failure: ArgoCdFailure) => {
  switch (failure.kind) {
    case "unreachable":
      return failure.timedOut
        ? "no answer in time"
        : `no answer (${describeFailure(failure) ?? "unknown"})`;
    case "anonymous":
      return "answered as to an anonymous caller";
    case "not_managed":
      return "the Application doesn't manage the resource";
    case "status":
      return `answered ${failure.status}`;
    case "unexpected":
      return `unexpected answer (${failure.reason})`;
  }
};

/**
 * An Argo CD call that failed.
 *
 * It holds the call's template and how it failed, and nothing of the
 * request: not the URL, whose path and query carry names, and not the
 * headers, which carry the token. Nor a `cause`: `fetch`'s errors can quote
 * the request. Only a `not_managed` failure names its Application and
 * namespace, which is what P0 needs to be told.
 */
export class ArgoCdError extends Error {
  constructor(
    readonly call: ArgoCdCall,
    readonly failure: ArgoCdFailure
  ) {
    super(`Argo CD ${call.method} ${call.route}: ${describe(failure)}`);
    this.name = "ArgoCdError";
  }
}

/** Whether `error` is an Argo CD call that answered `status`. */
export const isStatus = (error: unknown, status: number): boolean =>
  error instanceof ArgoCdError &&
  error.failure.kind === "status" &&
  error.failure.status === status;

const refuseName = (value: string) =>
  new ConnectorError({
    type: "validation_error",
    message: `"${value}" isn't a valid Argo CD name.`,
    payload: { segment: value },
  });

/**
 * One URL path segment.
 *
 * `encodeURIComponent` leaves `.` and `..` alone, and `fetch` would resolve
 * them, so an Application named `..` would turn `/applications/../resource`
 * into `/resource`. The input schemas refuse them already. This refuses them
 * again where it matters.
 *
 * Copied from services/p0-connector-harbor/src/harbor/api.ts. Exported for
 * its tests.
 */
// TODO(INT-446): merge the copies into one shared encoder.
export const segment = (value: string): string => {
  if (value === "" || value === "." || value === "..") throw refuseName(value);
  return encodeURIComponent(value);
};

/**
 * A `**` path part, such as can-i's object `*\/*` or `<project>/<app>`: its
 * slashes stay slashes, and each piece between them is a {@link segment}.
 *
 * Argo CD's gateway reads the rest of the path as the value, slashes
 * included, and doesn't decode a `%2F`: an object sent as `*%2F*` is
 * another object, which can-i quietly answers `no`.
 */
export const pathParts = (value: string): string =>
  value.split("/").map(segment).join("/");

/**
 * The answer's body as text, or `undefined` when it is longer than
 * {@link MAX_ANSWER_BYTES}. It is read as it arrives and dropped at the cap,
 * so a body of any length costs the connector no more than the cap.
 */
const readBounded = async (response: Response): Promise<string | undefined> => {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return Buffer.concat(chunks).toString("utf8");
    size += value.byteLength;
    if (size > MAX_ANSWER_BYTES) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
};

type Target = {
  call: ArgoCdCall;
  /** The path, values already through {@link segment} or {@link pathParts}. */
  path: ArgoCdPath;
  query?: Record<string, string>;
};

/** Argo CD's API, as one account's token on one instance. */
export type ArgoCdApi = {
  /** A call whose 2xx answer is read, and must be `answer`'s shape. */
  read: <T>(request: Target & { answer: z.ZodType<T> }) => Promise<T>;
  /** A call whose answer's body isn't read. `body` goes as JSON. */
  send: (request: Target & { body?: unknown }) => Promise<void>;
  /**
   * The error for an answer Argo CD wouldn't give, logged. For checks the
   * caller makes on answers that parsed, such as a manifest's.
   */
  unexpected: (call: ArgoCdCall, reason: UnexpectedAnswer) => ArgoCdError;
};

/**
 * The token as it goes in the header: trimmed, since a stored token often
 * ends in a newline, and refused unless what is left is printable ASCII.
 * An Argo CD token is a JWT, which is. A space or a control character inside
 * would change the header, or make `fetch` throw an error that quotes it.
 */
const bearerToken = (token: string): string => {
  const trimmed = token.trim();
  if (!/^[\x21-\x7e]+$/.test(trimmed)) {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "The connector's Argo CD API token is empty, or has a space, a control character or a non-ASCII character in it. Store the p0-connector account's API token exactly as Argo CD generated it.",
      payload: {},
    });
  }
  return trimmed;
};

/**
 * Makes Argo CD calls with `token`, on the instance at `origin`.
 *
 * The token lives only in this closure and in the `Authorization` header it
 * sends: nothing that holds it is returned, logged or thrown. It is checked
 * before any call is made ({@link bearerToken}).
 *
 * Every call:
 * - goes to `origin`, which must be https;
 * - sends `Authorization: Bearer <token>`;
 * - gives up after {@link ARGOCD_TIMEOUT_MS}, its body included;
 * - follows no redirect, since only `origin` was checked and the call carries
 *   the token: a 3xx is a failed status;
 * - sends no cookie, so Argo CD reads the bearer token and nothing else;
 * - reads at most {@link MAX_ANSWER_BYTES} of a 2xx, and nothing of any
 *   other status.
 *
 * A call that gets no answer, or one Argo CD wouldn't give, is logged as a
 * warning. A status outside 2xx is logged at debug only: the caller decides
 * what it means (a 400 from a resource route is an answer), and the route
 * logs what reaches P0.
 */
export const newArgoCdApi = ({
  origin,
  token,
  logger,
}: {
  origin: string;
  token: string;
  logger: Logger;
}): ArgoCdApi => {
  if (new URL(origin).protocol !== "https:") {
    // The instance schema refuses this already.
    throw new ConnectorError({
      type: "validation_error",
      message: "The connector only calls Argo CD over https.",
      payload: {},
    });
  }
  const authorization = `Bearer ${bearerToken(token)}`;

  const unexpected = (
    call: ArgoCdCall,
    reason: UnexpectedAnswer,
    fields: Record<string, unknown> = {}
  ) => {
    logger.warn(
      { method: call.method, route: call.route, reason, ...fields },
      "Argo CD's answer isn't one Argo CD gives"
    );
    return new ArgoCdError(call, { kind: "unexpected", reason });
  };

  /**
   * Makes the call. Returns the body of a 2xx when `read` asks for it, as
   * text, or `undefined` when it is over the cap.
   */
  const exchange = async ({
    call,
    path,
    query,
    body,
    read,
  }: Target & { body?: unknown; read: boolean }) => {
    const { method, route } = call;
    const search = query ? `?${new URLSearchParams(query).toString()}` : "";

    let status: number;
    let text: string | undefined;
    try {
      const response = await fetch(`${origin}${path}${search}`, {
        method,
        headers: {
          Accept: "application/json",
          Authorization: authorization,
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        redirect: "manual",
        signal: AbortSignal.timeout(ARGOCD_TIMEOUT_MS),
      });
      status = response.status;
      // Only a 2xx the caller reads has a body worth reading.
      if (response.ok && read) {
        text = await readBounded(response);
      } else {
        await response.body?.cancel();
      }
    } catch (error) {
      // `fetch` throws a bare "fetch failed" and keeps what happened in
      // `cause`. A body that breaks off throws what broke it. Either is
      // described, never kept: both can quote the request.
      const cause: unknown =
        error instanceof Error && error.cause !== undefined
          ? error.cause
          : error;
      const { code, name } = failureFacts(cause);
      const failure: ArgoCdFailure = {
        kind: "unreachable",
        timedOut: error instanceof Error && error.name === "TimeoutError",
        ...(code === undefined ? {} : { code }),
        ...(name === undefined ? {} : { name }),
      };
      logger.warn({ method, route, ...failure }, "Argo CD call got no answer");
      throw new ArgoCdError(call, failure);
    }

    if (status < 200 || status >= 300) {
      logger.debug({ method, route, status }, "Argo CD call answered");
      throw new ArgoCdError(call, { kind: "status", status });
    }
    logger.debug({ method, route, status }, "Argo CD call succeeded");
    return text;
  };

  return {
    read: async ({ answer, ...target }) => {
      const text = await exchange({ ...target, read: true });
      if (text === undefined) throw unexpected(target.call, "too_large");
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        throw unexpected(target.call, "not_json");
      }
      const parsed = answer.safeParse(json);
      if (!parsed.success) {
        // Where the answer went wrong, never what it held.
        throw unexpected(target.call, "wrong_shape", {
          issues: parsed.error.issues.map(({ code, path }) => ({
            code,
            path: path.map(String).join("."),
          })),
        });
      }
      return parsed.data;
    },
    send: async (request) => {
      await exchange({ ...request, read: false });
    },
    unexpected: (call, reason) => unexpected(call, reason),
  };
};
