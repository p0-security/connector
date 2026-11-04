import { ConnectorError, throwAssertNever } from "@p0security/connector-core";

import { renderFailure } from "../failure.ts";
import {
  CLOUDFLARE_ROUTES,
  CLOUDFLARE_TIMEOUT_MS,
  CloudflareError,
} from "./cloudflare-api.ts";

/** The statuses Cloudflare refuses a call with because of the call itself. */
const REFUSAL_STATUSES: ReadonlySet<number> = new Set([400, 405, 409, 422]);

/** The message for a mint refused at the account's token cap (spec section 4). */
export const TOKEN_CAP_MESSAGE =
  "This Cloudflare account has reached its limit of 500 API tokens. Delete unused tokens and retry.";

/**
 * The error for a Cloudflare call that failed, as P0 shows it.
 *
 * A message names the call by its route template and its status, never by
 * its URL, and never quotes Cloudflare's own message, which can echo the
 * request. Cloudflare's codes go in `payload.codes`.
 *
 * | Failure                                   | Type                      |
 * | ----------------------------------------- | ------------------------- |
 * | a mint refused with a 4xx naming a limit  | `validation_error`        |
 * | 401, 403                                  | `insufficient_privileges` |
 * | 404                                       | `object_not_found`        |
 * | 400, 405, 409, 422                        | `validation_error`        |
 * | 429                                       | `rate_limited`            |
 * | 5xx, or no answer                         | `upstream_unavailable`    |
 * | a redirect, or any other status           | `validation_error`        |
 * | a 2xx Cloudflare wouldn't send            | `unknown`                 |
 */
const fromCloudflareError = ({
  call,
  failure,
}: CloudflareError): ConnectorError => {
  const { method, route } = call;
  switch (failure.kind) {
    case "unreachable": {
      const reason = failure.timedOut
        ? `no answer within ${CLOUDFLARE_TIMEOUT_MS / 1000} seconds`
        : (renderFailure(failure) ?? "the request failed");
      const { code } = failure;
      return new ConnectorError({
        message: `The connector couldn't reach Cloudflare: ${reason}. Check that the connector's network can reach api.cloudflare.com, and try again.`,
        payload: code === undefined ? {} : { code },
        type: "upstream_unavailable",
      });
    }
    case "unexpected":
      return new ConnectorError({
        message: `Cloudflare answered ${method} ${route} with something the connector can't read (${failure.reason}). Try again, and contact P0 support if it keeps happening.`,
        payload: { reason: failure.reason },
        type: "unknown",
      });
    case "status": {
      const { status, codes, limitReached } = failure;
      const payload = {
        status,
        ...(codes.length === 0 ? {} : { codes: codes.join(",") }),
      };
      // Cloudflare documents no code for the cap, so a mint's 4xx that
      // names a limit is taken as the cap. A 429 is the rate limit.
      if (
        call === CLOUDFLARE_ROUTES.createToken &&
        limitReached &&
        status >= 400 &&
        status < 500 &&
        status !== 401 &&
        status !== 429
      ) {
        return new ConnectorError({
          message: TOKEN_CAP_MESSAGE,
          payload,
          type: "validation_error",
        });
      }
      if (status === 401) {
        return new ConnectorError({
          message: `Cloudflare didn't accept the connector's install token on ${method} ${route} (401). Check that the token in the secret is current and active, and that its IP filter, if any, allows the connector.`,
          payload,
          type: "insufficient_privileges",
        });
      }
      if (status === 403) {
        return new ConnectorError({
          message: `Cloudflare refused ${method} ${route} with 403: the install token's permission groups don't allow it.`,
          payload,
          type: "insufficient_privileges",
        });
      }
      if (status === 404) {
        return new ConnectorError({
          message: `Cloudflare found nothing for ${method} ${route} (404). Check the account ID on the Cloudflare account in P0, and that the token belongs to that account.`,
          payload,
          type: "object_not_found",
        });
      }
      if (status === 429) {
        return new ConnectorError({
          message: `Cloudflare is limiting the account's API calls: it answered ${method} ${route} with 429. Try again in five minutes.`,
          payload,
          type: "rate_limited",
        });
      }
      if (status >= 500) {
        return new ConnectorError({
          message: `Cloudflare answered ${method} ${route} with ${status}. Try again later.`,
          payload,
          type: "upstream_unavailable",
        });
      }
      if (REFUSAL_STATUSES.has(status)) {
        return new ConnectorError({
          message: `Cloudflare refused ${method} ${route} with ${status}.`,
          payload,
          type: "validation_error",
        });
      }
      return new ConnectorError({
        message:
          status >= 300 && status < 400
            ? `Cloudflare answered ${method} ${route} with a redirect (${status}), which the connector doesn't follow. Contact P0 support if it keeps happening.`
            : `Cloudflare answered ${method} ${route} with ${status}, which the connector doesn't expect. Contact P0 support if it keeps happening.`,
        payload,
        type: "validation_error",
      });
    }
    default:
      throw throwAssertNever(failure);
  }
};

/**
 * Maps a failed Cloudflare call onto the {@link ConnectorError} P0 shows.
 * Anything else is returned as it is, so a bug stays a bug.
 */
export const toConnectorError = (error: unknown): unknown =>
  error instanceof CloudflareError ? fromCloudflareError(error) : error;
