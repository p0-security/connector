import { ConnectorError, type Logger } from "@p0security/connector-core";
import type { z } from "zod";

import { describeFailure, failureFacts } from "../failure.ts";

/** Where Harbor's API lives under the instance's origin. */
export const HARBOR_API = "/api/v2.0";

/** How long Harbor has to answer a call, its body included. */
export const HARBOR_TIMEOUT_MS = 10_000;

/**
 * The most of an answer the connector reads. A full page of 100 projects,
 * Harbor's largest answer the connector asks for, is well under 100 KiB. The
 * URL is whatever P0 sent, so what answers may send anything.
 */
export const MAX_ANSWER_BYTES = 1024 * 1024;

type Method = "DELETE" | "GET" | "HEAD" | "POST" | "PUT";

/**
 * What a call is, for its messages and its log lines.
 *
 * `route` is the path as Harbor's API reference writes it, with
 * `{placeholders}` for the values, so neither a message nor a log line
 * carries a project name, a member id or an email.
 */
export type HarborCall = {
  method: Method;
  route: `${typeof HARBOR_API}/${string}`;
};

/** Why an answer wasn't one Harbor gives. */
export type UnexpectedAnswer =
  "endless" | "not_json" | "too_large" | "too_many_rows" | "wrong_shape";

/** How a call failed. */
export type HarborFailure =
  /** No answer: `code` and `name` are Node's, and say what happened. */
  | {
      kind: "unreachable";
      timedOut: boolean;
      code?: number | string;
      name?: string;
    }
  /**
   * The project a call named doesn't exist, or no longer does. The client
   * tells this from a 403 with `HEAD /projects?project_name=`.
   */
  | { kind: "project_gone"; project: string }
  /** An answer outside 2xx. */
  | { kind: "status"; status: number }
  /** A 2xx with a body Harbor wouldn't send. */
  | { kind: "unexpected"; reason: UnexpectedAnswer };

const describe = (failure: HarborFailure) => {
  switch (failure.kind) {
    case "unreachable":
      return failure.timedOut
        ? "no answer in time"
        : `no answer (${describeFailure(failure) ?? "unknown"})`;
    case "status":
      return `answered ${failure.status}`;
    case "unexpected":
      return `unexpected answer (${failure.reason})`;
    case "project_gone":
      return "the project doesn't exist";
  }
};

/**
 * A Harbor call that failed.
 *
 * It holds the call's template and how it failed, and nothing of the
 * request: not the URL, whose path and query carry names and emails, and not
 * the headers, which carry the credential. Nor a `cause`: `fetch`'s errors
 * can quote the request. Only a `project_gone` failure names its project,
 * which is what P0 needs to be told.
 */
export class HarborError extends Error {
  constructor(
    readonly call: HarborCall,
    readonly failure: HarborFailure
  ) {
    super(`Harbor ${call.method} ${call.route}: ${describe(failure)}`);
    this.name = "HarborError";
  }
}

/** Whether `error` is a Harbor call that answered `status`. */
export const isStatus = (error: unknown, status: number): boolean =>
  error instanceof HarborError &&
  error.failure.kind === "status" &&
  error.failure.status === status;

/**
 * One URL path segment.
 *
 * `encodeURIComponent` leaves `.` and `..` alone, and `fetch` would resolve
 * them, so a project named `..` would turn `/projects/../members` into
 * `/members`. The input schemas refuse them already. This refuses them again
 * where it matters.
 *
 * Copied from services/p0-connector-github-repositories/src/github/api.ts,
 * with one difference: it refuses an empty segment too, which would make
 * `/projects//members`. Exported for its tests.
 */
// TODO(INT-446): merge the copies into one shared encoder.
export const segment = (value: string): string => {
  if (value === "" || value === "." || value === "..") {
    throw new ConnectorError({
      type: "validation_error",
      message: `"${value}" isn't a valid Harbor name.`,
      payload: { segment: value },
    });
  }
  return encodeURIComponent(value);
};

/**
 * The answer's body as text, or `undefined` when it is longer than
 * {@link MAX_ANSWER_BYTES}. It is read as it arrives and dropped at the cap,
 * so a body of any length costs the connector no more than the cap.
 * Exported for the identity provider's calls (oidc.ts).
 */
export const readBounded = async (
  response: Response
): Promise<string | undefined> => {
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
  call: HarborCall;
  /** The path below {@link HARBOR_API}, values already through {@link segment}. */
  path: string;
  query?: Record<string, string>;
};

/** Harbor's API, as the Harbor admin user on one instance. */
export type HarborApi = {
  /** A call whose 2xx answer is read, and must be `answer`'s shape. */
  read: <T>(request: Target & { answer: z.ZodType<T> }) => Promise<T>;
  /** A call whose answer's body isn't read. */
  send: (request: Target & { body?: unknown }) => Promise<void>;
  /**
   * The error for an answer Harbor wouldn't give, logged. For checks the
   * caller makes on answers that parsed, such as paging's.
   */
  unexpected: (call: HarborCall, reason: UnexpectedAnswer) => HarborError;
};

/**
 * Makes Harbor calls as the Harbor admin user, on the instance at `origin`,
 * with `Authorization: Bearer <ID token>`, which Harbor accepts in OIDC mode
 * from a user it knows (its src/server/middleware/security/idtoken.go). The
 * token is minted from the admin credential (oidc.ts).
 *
 * The token lives only in this closure and in the `Authorization` header it
 * sends: nothing that holds it is returned, logged or thrown.
 *
 * Every call:
 * - goes to `origin`, which must be https;
 * - gives up after {@link HARBOR_TIMEOUT_MS}, its body included;
 * - follows no redirect, since only `origin` was checked and the call carries
 *   the credential: a 3xx is a failed status;
 * - sends `X-Is-Resource-Name: true`, so Harbor reads a project segment as a
 *   name even when it looks like a number (a project named `123` would
 *   otherwise address project id 123);
 * - sends no cookie: Harbor's CSRF check skips `/api/` only for a request
 *   without a session cookie, and `fetch` keeps none;
 * - reads at most {@link MAX_ANSWER_BYTES} of a 2xx, and nothing of any
 *   other status.
 *
 * A call that gets no answer, or one Harbor wouldn't give, is logged as a
 * warning. A status outside 2xx is logged at debug only: the caller decides
 * what it means (a 404 from `HEAD /projects` is an answer, not a failure),
 * and the route logs what reaches P0.
 */
export const newHarborApi = ({
  origin,
  idToken,
  logger,
}: {
  origin: string;
  idToken: string;
  logger: Logger;
}): HarborApi => {
  if (new URL(origin).protocol !== "https:") {
    // The instance schema refuses this already.
    throw new ConnectorError({
      type: "validation_error",
      message: "The connector only calls Harbor over https.",
      payload: {},
    });
  }
  const authorization = `Bearer ${idToken}`;

  const unexpected = (
    call: HarborCall,
    reason: UnexpectedAnswer,
    fields: Record<string, unknown> = {}
  ) => {
    logger.warn(
      { method: call.method, route: call.route, reason, ...fields },
      "Harbor's answer isn't one Harbor gives"
    );
    return new HarborError(call, { kind: "unexpected", reason });
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
      const response = await fetch(`${origin}${HARBOR_API}${path}${search}`, {
        method,
        headers: {
          Accept: "application/json",
          Authorization: authorization,
          "X-Is-Resource-Name": "true",
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        redirect: "manual",
        signal: AbortSignal.timeout(HARBOR_TIMEOUT_MS),
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
      const failure: HarborFailure = {
        kind: "unreachable",
        timedOut: error instanceof Error && error.name === "TimeoutError",
        ...(code === undefined ? {} : { code }),
        ...(name === undefined ? {} : { name }),
      };
      logger.warn({ method, route, ...failure }, "Harbor call got no answer");
      throw new HarborError(call, failure);
    }

    if (status < 200 || status >= 300) {
      logger.debug({ method, route, status }, "Harbor call answered");
      throw new HarborError(call, { kind: "status", status });
    }
    logger.debug({ method, route, status }, "Harbor call succeeded");
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
