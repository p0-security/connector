import {
  ConnectorError,
  type ConnectorErrorType,
} from "@p0security/connector-core";
import { ResultCodeError } from "ldapts";

import { failureFacts } from "./failure.ts";

/** The server that a failed call went to, as a message names it. */
export type Server = "PingFederate" | "the user store";

const UNREACHABLE: ReadonlySet<unknown> = new Set([
  "EAI_AGAIN",
  "ECONNREFUSED",
  "ECONNRESET",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENOTFOUND",
  "ETIMEDOUT",
]);

const UNTRUSTED: ReadonlySet<unknown> = new Set([
  "CERT_HAS_EXPIRED",
  "CERT_UNTRUSTED",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
]);

// ldapts gives its timeouts no code.
const TIMED_OUT = /^Connection timeout$|Operation timed out$/;

const fromNetwork = (
  error: unknown,
  server: Server
): ConnectorError | undefined => {
  const { code } = failureFacts(error);
  const payload: Record<string, number | string> =
    code === undefined ? {} : { code };
  if (UNTRUSTED.has(code)) {
    return new ConnectorError({
      message: `The connector doesn't trust the TLS certificate of ${server} (${code}). If an internal CA issued it, add the CA's certificate to the PingFederate app in P0. Check also that the URL's host name is in the certificate.`,
      payload,
      type: "validation_error",
    });
  }
  const timedOut = error instanceof Error && TIMED_OUT.test(error.message);
  if (UNREACHABLE.has(code) || timedOut) {
    return new ConnectorError({
      message: `The connector couldn't reach ${server}: ${timedOut ? "no answer in time" : code}. Check the URL on the PingFederate app in P0, and that the connector's network reaches ${server}.`,
      payload,
      type: "upstream_unavailable",
    });
  }
  return undefined;
};

/** LDAP result codes (RFC 4511) that the connector names. */
const RESULTS: Record<number, { type: ConnectorErrorType; message: string }> = {
  3: {
    type: "upstream_unavailable",
    message: "The user store's time limit ended the request. Try again.",
  },
  32: {
    type: "object_not_found",
    message:
      "The user store has no such entry. Check the base DN on the PingFederate app in P0.",
  },
  49: {
    type: "insufficient_privileges",
    message:
      "The user store didn't accept the bind account. Check the bind DN on the PingFederate app in P0, and that the secret holds the bind account's current password.",
  },
  50: {
    type: "insufficient_privileges",
    message:
      "The user store refused the bind account access. Give the bind account read access to the base DN and the schema.",
  },
  51: {
    type: "upstream_unavailable",
    message: "The user store is busy. Try again later.",
  },
  52: {
    type: "upstream_unavailable",
    message: "The user store is unavailable. Try again later.",
  },
};

const fromResult = ({ code }: ResultCodeError): ConnectorError => {
  const known = RESULTS[code];
  return new ConnectorError({
    ...(known ?? {
      type: "validation_error",
      message: `The user store refused the request with LDAP result ${code}.`,
    }),
    payload: { ldapResult: code },
  });
};

/**
 * Maps a failed call to the user store or to PingFederate onto the
 * {@link ConnectorError} P0 shows. Anything else is returned as it is.
 */
export const toConnectorError = (error: unknown, server: Server): unknown => {
  if (error instanceof ConnectorError) return error;
  if (error instanceof ResultCodeError) return fromResult(error);
  return fromNetwork(error, server) ?? error;
};
