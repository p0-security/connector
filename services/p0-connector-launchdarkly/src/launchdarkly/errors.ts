import { ConnectorError, throwAssertNever } from "@p0security/connector";

import { renderFailure } from "../failure.ts";
import { LAUNCHDARKLY_TIMEOUT_MS, LaunchDarklyError } from "./api.ts";

/**
 * The statuses LaunchDarkly refuses a call with because of the call itself
 * (its "HTTP status error response codes"): a body it can't read, a verb a
 * route doesn't take, a concurrent change, a patch it can't apply.
 */
const REFUSAL_STATUSES: ReadonlySet<number> = new Set([400, 405, 409, 422]);

/**
 * The error for a LaunchDarkly call that failed, as P0 shows it.
 *
 * A message names the call by its route template, its status and the
 * instance's host, never by its URL. It quotes LaunchDarkly's own `message`
 * only for a write that LaunchDarkly refused, where it says what was wrong
 * with the change: the API keeps it for writes only, since a read's can
 * echo what was asked, an email among it.
 *
 * | Failure                         | Type                      |
 * | ------------------------------- | ------------------------- |
 * | 401, 403                        | `insufficient_privileges` |
 * | 404                             | `object_not_found`        |
 * | 400, 405, 409, 422              | `validation_error`        |
 * | 429                             | `rate_limited`            |
 * | 5xx, or no answer               | `upstream_unavailable`    |
 * | a redirect, or any other status | `validation_error`        |
 * | a 2xx LaunchDarkly wouldn't send | `unknown`                |
 */
const fromLaunchDarklyError = (
  { call: { method, route }, failure }: LaunchDarklyError,
  host: string
): ConnectorError => {
  switch (failure.kind) {
    case "unreachable": {
      const reason = failure.timedOut
        ? `no answer within ${LAUNCHDARKLY_TIMEOUT_MS / 1000} seconds`
        : (renderFailure(failure) ?? "the request failed");
      const { code } = failure;
      return new ConnectorError({
        message: `The connector couldn't reach LaunchDarkly at ${host}: ${reason}. Check that the connector's network can reach it, and try again.`,
        payload: { host, ...(code === undefined ? {} : { code }) },
        type: "upstream_unavailable",
      });
    }
    case "unexpected":
      return new ConnectorError({
        message: `LaunchDarkly at ${host} answered ${method} ${route} with something the connector can't read (${failure.reason}). Try again, and contact P0 support if it keeps happening.`,
        payload: { host, reason: failure.reason },
        type: "unknown",
      });
    case "status": {
      const { status, message, retryAfter } = failure;
      const payload = { host, status };
      if (status === 401) {
        return new ConnectorError({
          message: `LaunchDarkly at ${host} didn't accept the connector's access token on ${method} ${route} (401). Check that the token in the secret is current and belongs to this account: a reset or expired token is refused.`,
          payload,
          type: "insufficient_privileges",
        });
      }
      if (status === 403) {
        return new ConnectorError({
          message: `LaunchDarkly at ${host} refused ${method} ${route} with 403: the access token's role doesn't allow it. Ask your P0 admin to check the token's permissions against the account's setup page in P0.`,
          payload,
          type: "insufficient_privileges",
        });
      }
      if (status === 404) {
        return new ConnectorError({
          message: `LaunchDarkly at ${host} found nothing for ${method} ${route} (404). Check that it still exists in LaunchDarkly, then try again.`,
          payload,
          type: "object_not_found",
        });
      }
      if (status === 429) {
        return new ConnectorError({
          message: `LaunchDarkly at ${host} is limiting the connector's calls: it answered ${method} ${route} with 429. Try again ${retryAfter === undefined ? "later" : `in ${retryAfter} seconds`}.`,
          payload: {
            ...payload,
            ...(retryAfter === undefined ? {} : { retryAfter }),
          },
          type: "rate_limited",
        });
      }
      if (status >= 500) {
        return new ConnectorError({
          message: `LaunchDarkly at ${host} answered ${method} ${route} with ${status}. Try again later.`,
          payload,
          type: "upstream_unavailable",
        });
      }
      if (REFUSAL_STATUSES.has(status)) {
        return new ConnectorError({
          message: `LaunchDarkly at ${host} refused ${method} ${route} with ${status}${message === undefined ? "" : `: ${message}`}.`,
          payload,
          type: "validation_error",
        });
      }
      return new ConnectorError({
        message:
          status >= 300 && status < 400
            ? `LaunchDarkly at ${host} answered ${method} ${route} with a redirect (${status}), which the connector doesn't follow. Contact P0 support if it keeps happening.`
            : `LaunchDarkly at ${host} answered ${method} ${route} with ${status}, which the connector doesn't expect. Contact P0 support if it keeps happening.`,
        payload,
        type: "validation_error",
      });
    }
    default:
      throw throwAssertNever(failure);
  }
};

/**
 * Maps a failed LaunchDarkly call onto the {@link ConnectorError} P0 shows.
 * `host` is the instance's, which stands for the account in messages.
 *
 * A `ConnectorError` passes as it is. Anything else that isn't a
 * LaunchDarkly failure is returned as it is too, so a bug stays a bug rather
 * than being dressed up as LaunchDarkly's.
 */
export const toConnectorError = (error: unknown, host: string): unknown =>
  error instanceof LaunchDarklyError
    ? fromLaunchDarklyError(error, host)
    : error;

/**
 * Runs LaunchDarkly calls, mapping any failure through
 * {@link toConnectorError}. Nothing is retried: P0 decides what to do with a
 * `rate_limited` or an `upstream_unavailable`.
 */
export const callLaunchDarkly = async <T>(
  fn: () => Promise<T>,
  host: string
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    throw toConnectorError(error, host);
  }
};
