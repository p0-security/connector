import { ConnectorError } from "@p0security/connector";

import { describeFailure } from "../failure.ts";
import { refusal } from "../refusals.ts";
import { HARBOR_TIMEOUT_MS, HarborError } from "./api.ts";

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
 * The other statuses Harbor refuses a call with (src/lib/errors/const.go):
 * the call itself was wrong.
 */
const HARBOR_REFUSAL_STATUSES: ReadonlySet<number> = new Set([
  400, 405, 412, 422,
]);

/**
 * Harbor's 401: it didn't accept the ID token. Harbor treats a token it can't
 * verify, or one whose subject and issuer belong to no Harbor user, as an
 * anonymous caller, and a route that needs a user answers that 401.
 */
export const tokenRejected = (host: string, status?: number) =>
  refusal({
    reason: "admin_token_rejected",
    message: `Harbor at ${host} didn't accept the ID token the connector minted for its admin account. Check that the admin credential's clientId is Harbor's OIDC client ID, that the admin account has signed in to Harbor once, and that Harbor signs users in with OIDC.`,
    payload: { host, ...(status === undefined ? {} : { status }) },
  });

/**
 * Harbor's 403 to the admin user, or a `sysadmin_flag` install validation
 * finds unset: the account isn't a Harbor system administrator.
 */
export const notHarborAdmin = (host: string, status?: number) =>
  refusal({
    reason: "admin_not_harbor_admin",
    message: `The admin account the connector signs in to Harbor at ${host} with isn't a Harbor system administrator. Make it one on Harbor's Users page.`,
    payload: { host, ...(status === undefined ? {} : { status }) },
  });

/**
 * The error for a Harbor call that failed, as P0 shows it.
 *
 * A message names the call by its route template, its status and the
 * instance's host. It never quotes what Harbor said: a server at a wrong URL
 * may answer with anything, and Harbor's 401 and 403 bodies are generic
 * anyway.
 */
const fromHarborError = (
  { call: { method, route }, failure }: HarborError,
  host: string
): ConnectorError => {
  const notHarbor = (status?: number) =>
    new ConnectorError({
      type: "validation_error",
      message: `${host} didn't answer ${method} ${route} the way Harbor does${status === undefined ? "" : `: it answered ${status}`}. Check that the instance's URL points at Harbor.`,
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
        ? `no answer within ${HARBOR_TIMEOUT_MS / 1000} seconds`
        : (describeFailure(failure) ?? "the request failed");
      return new ConnectorError({
        type: "upstream_unavailable",
        message: `The connector couldn't reach Harbor at ${host}: ${reason}. Check the instance's URL, and that the connector's network can reach it.`,
        payload: { host },
      });
    }
    case "unexpected":
      return notHarbor();
    case "project_gone":
      // Not `object_not_found`: P0 turns that into a NotFoundError, which
      // reaches the requester as a bare "Not found". A `validation_error`
      // keeps this message. `reason` is how a revoke recognises it, and
      // treats it as done.
      return refusal({
        reason: "project_gone",
        message: `Project ${failure.project} no longer exists on ${host}.`,
        payload: { host, project: failure.project },
      });
    case "status": {
      const { status } = failure;
      if (status === 401) return tokenRejected(host, status);
      if (status === 403) return notHarborAdmin(host, status);
      if (status === 409) {
        return new ConnectorError({
          type: "already_exists",
          message: `Harbor at ${host} answered ${method} ${route} with 409: what the call would add is there already.`,
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
          message: `${host} answered ${method} ${route} with ${status}. Check that Harbor is running, and try again.`,
          payload: { host, status },
        });
      }
      // Every route the connector calls exists. A project's routes can answer
      // 404, when a delete lands between Harbor's two lookups of the project
      // (INT-265, item 4), but the client turns that into `project_gone`
      // before it gets here. So a 404, like a redirect or a status Harbor
      // never sends, is how something else answers.
      if (!HARBOR_REFUSAL_STATUSES.has(status)) return notHarbor(status);
      return new ConnectorError({
        type: "validation_error",
        message: `Harbor at ${host} refused ${method} ${route} with ${status}.`,
        payload: { host, status },
      });
    }
  }
};

/**
 * Maps a failed Harbor call onto the {@link ConnectorError} P0 shows.
 * `host` is the instance's, which stands for it in messages: the connector
 * doesn't know the install item's id.
 *
 * A `ConnectorError` passes as it is. Anything else that isn't a Harbor
 * failure is returned as it is too, so a bug stays a bug rather than being
 * dressed up as Harbor's.
 */
export const toConnectorError = (error: unknown, host: string): unknown =>
  error instanceof HarborError ? fromHarborError(error, host) : error;

/** Runs Harbor calls, mapping any failure through {@link toConnectorError}. */
export const callHarbor = async <T>(
  fn: () => Promise<T>,
  host: string
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    throw toConnectorError(error, host);
  }
};
