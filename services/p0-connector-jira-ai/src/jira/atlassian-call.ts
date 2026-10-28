import { ConnectorError, type Logger } from "@p0security/connector-core";

/** How many times a call is sent, at most. */
export const MAX_ATTEMPTS = 4;

/** The longest one attempt may take. */
export const ATTEMPT_TIMEOUT_MS = 10_000;

/** The backoff before the first retry is up to this long, then doubles. */
export const BASE_DELAY_MS = 1_000;

/**
 * The longest one connector request (a grant, a revoke or an install lookup)
 * spends on Atlassian and on reading the admin client secret, attempts and
 * waits together, across all its calls. P0 holds its pool lock for 60
 * seconds while it calls the connector, so this leaves half of it for a
 * Cloud Run cold start and P0's own work before the call. A token grant's
 * read of the pool account's API key keeps to the same budget.
 */
export const REQUEST_BUDGET_MS = 30_000;

/** The deadline for a connector request that starts now. */
export const requestDeadline = () => Date.now() + REQUEST_BUDGET_MS;

export type AtlassianCall = {
  url: string;
  /** Everything but the signal, which each attempt gets fresh. */
  init: Omit<RequestInit, "signal">;
  /**
   * Whether sending the call again has no further effect. A call that isn't
   * is sent once.
   */
  repeatable: boolean;
  /** What the call does, for messages and log lines. */
  operation: string;
  /**
   * When the connector request's budget runs out, in epoch milliseconds,
   * shared by every call the request makes. See {@link requestDeadline}.
   */
  deadline: number;
  logger: Logger;
};

/** A rate limit or a server error, which may pass on its own. */
export const isTransient = (status: number) => status === 429 || status >= 500;

/** Atlassian's `Retry-After`, in seconds or as an HTTP date. */
const retryAfterMs = (response: Response): number | undefined => {
  const value = response.headers.get("retry-after");
  if (value === null || value.trim() === "") return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const date = Date.parse(value);
  return Number.isNaN(date) ? undefined : Math.max(0, date - Date.now());
};

/** Exponential backoff with full jitter, for the `retry`th retry (from 0). */
const backoffMs = (retry: number) => Math.random() * BASE_DELAY_MS * 2 ** retry;

const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

/** The failure for a request whose budget ran out while it retried. */
const outOfTime = (operation: string, rateLimited: boolean) =>
  new ConnectorError({
    type: rateLimited ? "rate_limited" : "upstream_unavailable",
    message: rateLimited
      ? `Atlassian is rate limiting the connector, so it couldn't ${operation} in time. Try the request again in a few minutes.`
      : `Atlassian is unavailable, so the connector couldn't ${operation} in time. Try the request again in a few minutes.`,
    payload: {},
  });

/**
 * Sends one call to Atlassian, retrying a 429, a 5xx, a network failure or a
 * timeout. It waits out `Retry-After` when Atlassian sends one, and an
 * exponential backoff with jitter otherwise, for at most
 * {@link MAX_ATTEMPTS} attempts, and never past the request's `deadline`.
 *
 * Every Atlassian call in the connector goes through here. The caller turns
 * the answer into an error: this neither reads a body it returns nor logs the
 * URL or headers, which may hold a path or a token.
 *
 * @returns The last response, which may be a failure
 * @throws ConnectorError (`rate_limited` or `upstream_unavailable`) when the
 * deadline passes before the call gets through
 * @throws The last network or timeout error
 */
export const callAtlassian = (call: AtlassianCall): Promise<Response> =>
  sendAttempt(call, 1, false);

/** An attempt's answer, or why and how long to wait before the next one. */
type AttemptResult =
  | {
      delay: number;
      failure: { error: string } | { status: number };
      rateLimited: boolean;
    }
  | { response: Response };

/**
 * Sends attempt number `attempt` of `call`, then the next ones as
 * {@link callAtlassian} describes. `rateLimited` is whether the attempt
 * before it got a 429.
 */
const sendAttempt = async (
  call: AtlassianCall,
  attempt: number,
  rateLimited: boolean
): Promise<Response> => {
  const { url, init, repeatable, operation, deadline, logger } = call;
  const left = deadline - Date.now();
  if (left <= 0) throw outOfTime(operation, rateLimited);
  const final = !repeatable || attempt >= MAX_ATTEMPTS;
  const signal = AbortSignal.timeout(Math.min(ATTEMPT_TIMEOUT_MS, left));
  const result = await fetch(url, { ...init, signal }).then(
    async (response): Promise<AttemptResult> => {
      if (final || !isTransient(response.status)) return { response };
      await response.body?.cancel().catch(() => undefined);
      return {
        delay: retryAfterMs(response) ?? backoffMs(attempt - 1),
        failure: { status: response.status },
        rateLimited: response.status === 429,
      };
    },
    (error: unknown): AttemptResult => {
      if (Date.now() >= deadline) throw outOfTime(operation, rateLimited);
      if (final) throw error;
      const name = error instanceof Error ? error.name : "unknown";
      return {
        delay: backoffMs(attempt - 1),
        failure: { error: name },
        rateLimited: false,
      };
    }
  );
  if ("response" in result) return result.response;
  const { delay, failure, rateLimited: limited } = result;
  if (Date.now() + delay >= deadline) throw outOfTime(operation, limited);
  logger.warn(
    { operation, attempt, delayMs: Math.round(delay), ...failure },
    "the Atlassian call failed, so the connector will retry it"
  );
  await sleep(delay);
  return await sendAttempt(call, attempt + 1, limited);
};
