import {
  ConnectorError,
  type ConnectorErrorType,
  throwAssertNever,
} from "@p0security/connector-core";

import { PINGONE_ROUTES, PINGONE_TIMEOUT_MS, PingOneError } from "./client.ts";

/** The token endpoint's OAuth errors, by `error`. */
const TOKEN_ERRORS: Record<
  string,
  { type: ConnectorErrorType; message: string }
> = {
  invalid_client: {
    type: "insufficient_privileges",
    message:
      "PingOne didn't accept the worker app's client ID or client secret. Check the client ID and the environment on the PingOne app in P0, and that the secret holds the worker app's current client secret.",
  },
  unauthorized_client: {
    type: "validation_error",
    message:
      'PingOne refused the worker app\'s token request. Set the worker app\'s grant type to "Client Credentials" and its token endpoint authentication method to "Client Secret Basic".',
  },
};

const fromPingOneError = ({ call, failure }: PingOneError): ConnectorError => {
  const { method, route } = call;
  switch (failure.kind) {
    case "unreachable": {
      const reason = failure.timedOut
        ? `no answer within ${PINGONE_TIMEOUT_MS / 1000} seconds`
        : (failure.code?.toString() ?? "the request failed");
      return new ConnectorError({
        message: `The connector couldn't reach PingOne: ${reason}. Check that the connector's network can reach PingOne in the app's region, and try again.`,
        payload: failure.code === undefined ? {} : { code: failure.code },
        type: "upstream_unavailable",
      });
    }
    case "unexpected":
      return new ConnectorError({
        message: `PingOne answered ${method} ${route} with something the connector can't read. Try again, and contact P0 support if it keeps happening.`,
        payload: {},
        type: "unknown",
      });
    case "status": {
      const { status, code } = failure;
      const payload = { status, ...(code === undefined ? {} : { code }) };
      const tokenError =
        call === PINGONE_ROUTES.token && code !== undefined
          ? TOKEN_ERRORS[code]
          : undefined;
      if (tokenError !== undefined) {
        return new ConnectorError({ ...tokenError, payload });
      }
      const failed = (type: ConnectorErrorType, message: string) =>
        new ConnectorError({ message, payload, type });
      if (status === 401) {
        return failed(
          "insufficient_privileges",
          `PingOne didn't accept the connector's access token on ${method} ${route} (401).`
        );
      }
      if (status === 403) {
        return failed(
          "insufficient_privileges",
          `PingOne refused ${method} ${route} with 403. Check that the worker app has the roles the connector needs, on the app's environment.`
        );
      }
      if (status === 404) {
        return failed(
          "object_not_found",
          `PingOne found nothing for ${method} ${route} (404). Check the region, the environment ID and the app ID on the PingOne app in P0.`
        );
      }
      if (status === 429) {
        return failed(
          "rate_limited",
          `PingOne is limiting the environment's API calls: it answered ${method} ${route} with 429. Try again in a minute.`
        );
      }
      if (status >= 500) {
        return failed(
          "upstream_unavailable",
          `PingOne answered ${method} ${route} with ${status}. Try again later.`
        );
      }
      return failed(
        "validation_error",
        `PingOne refused ${method} ${route} with ${status}.`
      );
    }
    default:
      throw throwAssertNever(failure);
  }
};

/**
 * Maps a failed PingOne call onto the {@link ConnectorError} P0 shows.
 * Anything else is returned as it is.
 */
export const toConnectorError = (error: unknown): unknown =>
  error instanceof PingOneError ? fromPingOneError(error) : error;
