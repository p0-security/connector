import { ConnectorError, throwAssertNever } from "@p0security/connector-core";

import { renderFailure } from "../failure.ts";
import { MIRO_TIMEOUT_MS, MiroError } from "./client.ts";

/** The statuses Miro refuses a call with because of the call itself. */
const REFUSAL_STATUSES: ReadonlySet<number> = new Set([400, 405, 409, 422]);

/**
 * The error for a Miro call that failed, as P0 shows it.
 *
 * A message names the call by its route template and its status, never by
 * its URL, and never quotes Miro's own message, which can echo the request.
 *
 * | Failure                         | Type                      |
 * | ------------------------------- | ------------------------- |
 * | 401, 403                        | `insufficient_privileges` |
 * | 404                             | `object_not_found`        |
 * | 400, 405, 409, 422              | `validation_error`        |
 * | 429, after the retries          | `rate_limited`            |
 * | 5xx, or no answer               | `upstream_unavailable`    |
 * | a redirect, or any other status | `validation_error`        |
 * | a 2xx Miro wouldn't send        | `unknown`                 |
 */
const fromMiroError = ({
  call: { method, route },
  failure,
}: MiroError): ConnectorError => {
  switch (failure.kind) {
    case "unreachable": {
      const reason = failure.timedOut
        ? `no answer within ${MIRO_TIMEOUT_MS / 1000} seconds`
        : (renderFailure(failure) ?? "the request failed");
      const { code } = failure;
      return new ConnectorError({
        message: `The connector couldn't reach Miro: ${reason}. Check that the connector's network can reach api.miro.com, and try again.`,
        payload: code === undefined ? {} : { code },
        type: "upstream_unavailable",
      });
    }
    case "unexpected":
      return new ConnectorError({
        message: `Miro answered ${method} ${route} with something the connector can't read (${failure.reason}). Try again, and contact P0 support if it keeps happening.`,
        payload: { reason: failure.reason },
        type: "unknown",
      });
    case "status": {
      const { status, retryAfter } = failure;
      const payload = { status };
      if (status === 401) {
        return new ConnectorError({
          message: `Miro didn't accept the connector's access token on ${method} ${route} (401). Check that the token in the secret is current: Miro revokes it when the connector user uninstalls the app.`,
          payload,
          type: "insufficient_privileges",
        });
      }
      if (status === 403) {
        return new ConnectorError({
          message: `Miro refused ${method} ${route} with 403: the access token's scopes, or the connector user's role, don't allow it.`,
          payload,
          type: "insufficient_privileges",
        });
      }
      if (status === 404) {
        return new ConnectorError({
          message: `Miro found nothing for ${method} ${route} (404). Check that it still exists in Miro, then try again.`,
          payload,
          type: "object_not_found",
        });
      }
      if (status === 429) {
        return new ConnectorError({
          message: `Miro is limiting the connector's calls: it answered ${method} ${route} with 429. Try again ${retryAfter === undefined ? "later" : `in ${retryAfter} seconds`}.`,
          payload: {
            ...payload,
            ...(retryAfter === undefined ? {} : { retryAfter }),
          },
          type: "rate_limited",
        });
      }
      if (status >= 500) {
        return new ConnectorError({
          message: `Miro answered ${method} ${route} with ${status}. Try again later.`,
          payload,
          type: "upstream_unavailable",
        });
      }
      if (REFUSAL_STATUSES.has(status)) {
        return new ConnectorError({
          message: `Miro refused ${method} ${route} with ${status}.`,
          payload,
          type: "validation_error",
        });
      }
      return new ConnectorError({
        message:
          status >= 300 && status < 400
            ? `Miro answered ${method} ${route} with a redirect (${status}), which the connector doesn't follow. Contact P0 support if it keeps happening.`
            : `Miro answered ${method} ${route} with ${status}, which the connector doesn't expect. Contact P0 support if it keeps happening.`,
        payload,
        type: "validation_error",
      });
    }
    default:
      throw throwAssertNever(failure);
  }
};

/**
 * Maps a failed Miro call onto the {@link ConnectorError} P0 shows. A
 * `ConnectorError` passes as it is. Anything else that isn't a Miro failure
 * is returned as it is too, so a bug stays a bug rather than being dressed
 * up as Miro's.
 */
export const toConnectorError = (error: unknown): unknown =>
  error instanceof MiroError ? fromMiroError(error) : error;
