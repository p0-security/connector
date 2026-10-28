// copy of services/p0-connector-harbor/src/harbor/errors.ts, for Argo CD's
// statuses and failures, without Harbor's refusals
import { ConnectorError } from "@p0security/connector-core";

import { describeFailure } from "../failure.ts";
import { ARGOCD_TIMEOUT_MS, ArgoCdError } from "./api.ts";

// How Node says it doesn't trust the certificate a host presented.
const CERTIFICATE_FAILURES: ReadonlySet<unknown> = new Set([
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "CERT_HAS_EXPIRED",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

/**
 * The other statuses Argo CD's gateway refuses a call with: the call itself
 * was wrong. gRPC's InvalidArgument and FailedPrecondition are 400, and
 * AlreadyExists and Aborted are 409.
 */
const ARGOCD_REFUSAL_STATUSES: ReadonlySet<number> = new Set([400, 409]);

/**
 * Argo CD didn't accept the token: a 401, or `loggedIn: false` from a route
 * that answers anyone. It is one answer for a token that is wrong, revoked or
 * expired, and for an account that is disabled or gone.
 */
export const tokenRejected = (host: string, status?: number) =>
  new ConnectorError({
    type: "insufficient_privileges",
    message: `Argo CD at ${host} didn't accept the connector's API token. Check that the secret holds a current API token of the p0-connector account, and that the account is enabled and has the apiKey capability.`,
    payload: { host, ...(status === undefined ? {} : { status }) },
  });

const forbidden = (
  { method, route, permission }: ArgoCdError["call"],
  host: string,
  status: number
) => {
  const payload = {
    host,
    status,
    ...(permission === undefined ? {} : { permission }),
  };
  if (permission === undefined) {
    return new ConnectorError({
      type: "insufficient_privileges",
      message: `Argo CD at ${host} refused the connector's call to ${method} ${route}.`,
      payload,
    });
  }
  // Argo CD answers 403 for an Application that doesn't exist, as it does
  // for one the caller may not read, so a 403 on an Application's routes
  // isn't always a missing permission.
  const onApplication = route.startsWith("/api/v1/applications/");
  return new ConnectorError({
    type: "insufficient_privileges",
    message: onApplication
      ? `Argo CD at ${host} refused the connector's call to ${method} ${route}. Either the p0-connector account doesn't have "${permission}" on the managing Application, or that Application doesn't exist: Argo CD answers both the same way. Check the managing Application on the Argo CD instance in P0, and the account's policy lines in argocd-rbac-cm.`
      : `Argo CD at ${host} refused the connector's call to ${method} ${route}. The p0-connector account needs "${permission}" in argocd-rbac-cm.`,
    payload,
  });
};

/**
 * The error for an Argo CD call that failed, as P0 shows it.
 *
 * A message names the call by its route template, its status and the
 * instance's host. It never quotes what Argo CD said: a server at a wrong URL
 * may answer with anything.
 */
const fromArgoCdError = (
  { call, failure }: ArgoCdError,
  host: string
): ConnectorError => {
  const { method, route } = call;
  const notArgoCd = (status?: number) =>
    new ConnectorError({
      type: "validation_error",
      message: `${host} didn't answer ${method} ${route} the way Argo CD does${status === undefined ? "" : `: it answered ${status}`}. Check that the instance's URL points at Argo CD.`,
      payload: { host, ...(status === undefined ? {} : { status }) },
    });

  switch (failure.kind) {
    case "unreachable": {
      const { code } = failure;
      // A host that doesn't resolve and a certificate Node doesn't trust are
      // the customer's to fix, so they say what to fix.
      if (code === "ENOTFOUND") {
        return new ConnectorError({
          type: "validation_error",
          message: `${host} doesn't resolve from the connector. Check the instance's URL, and that the connector's network can resolve its host.`,
          payload: { host, code },
        });
      }
      if (typeof code === "string" && CERTIFICATE_FAILURES.has(code)) {
        return new ConnectorError({
          type: "validation_error",
          message: `The connector doesn't trust the certificate ${host} presents (${code}). The certificate has to be valid for that host and chain to a public CA.`,
          payload: { host, code },
        });
      }
      const reason = failure.timedOut
        ? `no answer within ${ARGOCD_TIMEOUT_MS / 1000} seconds`
        : (describeFailure(failure) ?? "the request failed");
      return new ConnectorError({
        type: "upstream_unavailable",
        message: `The connector couldn't reach Argo CD at ${host}: ${reason}. Check the instance's URL, and that the connector's network can reach it.`,
        payload: { host },
      });
    }
    case "anonymous":
      return tokenRejected(host);
    case "not_managed":
      // Not `object_not_found`: P0 turns that into a NotFoundError, which
      // reaches the requester as a bare "Not found". A `validation_error`
      // keeps this message.
      return new ConnectorError({
        type: "validation_error",
        message: `Application ${failure.app} on ${host} doesn't manage ConfigMap ${failure.namespace}/argocd-rbac-cm. Check the managing Application and the namespace on the Argo CD instance in P0: the Application has to be the one that deploys argocd-rbac-cm.`,
        payload: { host, app: failure.app, namespace: failure.namespace },
      });
    case "unexpected":
      return notArgoCd();
    case "status": {
      const { status } = failure;
      if (status === 401) return tokenRejected(host, status);
      if (status === 403) return forbidden(call, host, status);
      if (status === 404) {
        return new ConnectorError({
          type: "validation_error",
          message: `${host} answered ${method} ${route} with 404. Check that the instance's URL points at Argo CD, served at its root, and the managing Application's name on the instance in P0.`,
          payload: { host, status },
        });
      }
      if (status === 429) {
        return new ConnectorError({
          type: "rate_limited",
          message: `${host} is limiting the connector's calls: it answered ${method} ${route} with 429. Try again later.`,
          payload: { host, status },
        });
      }
      if (status >= 500) {
        return new ConnectorError({
          type: "upstream_unavailable",
          message: `${host} answered ${method} ${route} with ${status}. Check that Argo CD is running, and try again.`,
          payload: { host, status },
        });
      }
      // A redirect, or a status Argo CD never sends, is how something else
      // answers.
      if (!ARGOCD_REFUSAL_STATUSES.has(status)) return notArgoCd(status);
      return new ConnectorError({
        type: "validation_error",
        message: `Argo CD at ${host} refused ${method} ${route} with ${status}.`,
        payload: { host, status },
      });
    }
  }
};

/**
 * Maps a failed Argo CD call onto the {@link ConnectorError} P0 shows.
 * `host` is the instance's, which stands for it in messages: the connector
 * doesn't know the install item's id.
 *
 * A `ConnectorError` passes as it is. Anything else that isn't an Argo CD
 * failure is returned as it is too, so a bug stays a bug rather than being
 * dressed up as Argo CD's.
 */
export const toConnectorError = (error: unknown, host: string): unknown =>
  error instanceof ArgoCdError ? fromArgoCdError(error, host) : error;

/** Runs Argo CD calls, mapping any failure through {@link toConnectorError}. */
export const callArgoCd = async <T>(
  fn: () => Promise<T>,
  host: string
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    throw toConnectorError(error, host);
  }
};
