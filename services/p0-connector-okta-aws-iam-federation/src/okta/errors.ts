import {
  ConnectorError,
  type ConnectorErrorType,
  throwAssertNever,
} from "@p0security/connector-core";

import {
  OKTA_ROUTES,
  OKTA_SCOPES,
  OKTA_TIMEOUT_MS,
  OktaError,
} from "./client.ts";

const SCOPES = OKTA_SCOPES.join(", ");

/** The token endpoint's OAuth errors, by `error`. */
const TOKEN_ERRORS: Record<
  string,
  { type: ConnectorErrorType; message: string }
> = {
  invalid_client: {
    type: "insufficient_privileges",
    message:
      "Okta didn't accept the service app's client ID or private key. Check the client ID on the Okta app in P0, and that the secret holds a current key of that service app, with its public key added in Okta.",
  },
  invalid_scope: {
    type: "insufficient_privileges",
    message: `Okta refused the scopes the connector asks for. Grant the service app these scopes: ${SCOPES}.`,
  },
  invalid_dpop_proof: {
    type: "validation_error",
    message:
      'The service app requires DPoP, which the connector doesn\'t send. Turn off "Require Demonstrating Proof of Possession (DPoP) header in token requests" on the service app in Okta.',
  },
};

const fromOktaError = ({ call, failure }: OktaError): ConnectorError => {
  const { method, route } = call;
  switch (failure.kind) {
    case "unreachable": {
      const reason = failure.timedOut
        ? `no answer within ${OKTA_TIMEOUT_MS / 1000} seconds`
        : (failure.code?.toString() ?? "the request failed");
      return new ConnectorError({
        message: `The connector couldn't reach Okta: ${reason}. Check that the connector's network can reach the Okta domain, and try again.`,
        payload: failure.code === undefined ? {} : { code: failure.code },
        type: "upstream_unavailable",
      });
    }
    case "unexpected":
      return new ConnectorError({
        message: `Okta answered ${method} ${route} with something the connector can't read. Try again, and contact P0 support if it keeps happening.`,
        payload: {},
        type: "unknown",
      });
    case "status": {
      const { status, code } = failure;
      const payload = { status, ...(code === undefined ? {} : { code }) };
      const tokenError =
        call === OKTA_ROUTES.token && code !== undefined
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
          `Okta didn't accept the connector's access token on ${method} ${route} (401).`
        );
      }
      if (status === 403) {
        return failed(
          "insufficient_privileges",
          `Okta refused ${method} ${route} with 403. Check that the service app has the scopes ${SCOPES}, and that its admin role covers the AWS app.`
        );
      }
      if (status === 404) {
        return failed(
          "object_not_found",
          `Okta found nothing for ${method} ${route} (404). Check the app ID on the Okta app in P0.`
        );
      }
      if (status === 429) {
        return failed(
          "rate_limited",
          `Okta is limiting the org's API calls: it answered ${method} ${route} with 429. Try again in a minute.`
        );
      }
      if (status >= 500) {
        return failed(
          "upstream_unavailable",
          `Okta answered ${method} ${route} with ${status}. Try again later.`
        );
      }
      return failed(
        "validation_error",
        `Okta refused ${method} ${route} with ${status}.`
      );
    }
    default:
      throw throwAssertNever(failure);
  }
};

/**
 * Maps a failed Okta call onto the {@link ConnectorError} P0 shows. Anything
 * else is returned as it is.
 */
export const toConnectorError = (error: unknown): unknown =>
  error instanceof OktaError ? fromOktaError(error) : error;
