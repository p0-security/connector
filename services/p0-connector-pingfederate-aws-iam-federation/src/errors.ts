import {
  ConnectorError,
  type ConnectorErrorType,
} from "@p0security/connector-core";

import { failureFacts } from "./failure.ts";
import { ScimReplyError, ScimStatusError } from "./pingfederate/scim.ts";

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

const fromNetwork = (error: unknown): ConnectorError | undefined => {
  const { code } = failureFacts(error);
  const payload: Record<string, number | string> =
    code === undefined ? {} : { code };
  if (UNTRUSTED.has(code)) {
    return new ConnectorError({
      message: `The connector doesn't trust the TLS certificate of PingFederate (${code}). If an internal CA issued it, add the CA's certificate to the PingFederate app in P0. Check also that the URL's host name is in the certificate.`,
      payload,
      type: "validation_error",
    });
  }
  if (UNREACHABLE.has(code)) {
    return new ConnectorError({
      message: `The connector couldn't reach PingFederate: ${code}. Check the PingFederate URL on the app in P0, and that the connector's network reaches PingFederate's runtime.`,
      payload,
      type: "upstream_unavailable",
    });
  }
  return undefined;
};

/** SCIM statuses that the connector names. */
const STATUSES: Record<number, { type: ConnectorErrorType; message: string }> =
  {
    401: {
      type: "insufficient_privileges",
      message:
        "PingFederate didn't accept the SCIM credentials. Check the SCIM user name on the PingFederate app in P0, and that the secret holds the current SCIM password.",
    },
    403: {
      type: "insufficient_privileges",
      message:
        "PingFederate refused the SCIM user access. Check that the SCIM IdP connection is active.",
    },
    429: {
      type: "rate_limited",
      message: "PingFederate is limiting requests. Try again later.",
    },
  };

const fromStatus = ({ status, detail }: ScimStatusError): ConnectorError => {
  const known = STATUSES[status];
  const said = detail === undefined ? "" : `: ${detail}`;
  return new ConnectorError({
    ...(known ??
      (status >= 500
        ? {
            type: "upstream_unavailable",
            message: `PingFederate failed the SCIM request with HTTP ${status}${said}. Check PingFederate's server log, and that its data store accepts the change.`,
          }
        : {
            type: "validation_error",
            message: `PingFederate refused the SCIM request with HTTP ${status}${said}.`,
          })),
    payload: { status },
  });
};

/**
 * Maps a failed call to PingFederate onto the {@link ConnectorError} P0
 * shows. Anything else is returned as it is.
 */
export const toConnectorError = (error: unknown): unknown => {
  if (error instanceof ConnectorError) return error;
  if (error instanceof ScimStatusError) return fromStatus(error);
  if (error instanceof ScimReplyError) {
    return new ConnectorError({
      message:
        "PingFederate's SCIM endpoint answered with something that isn't a SCIM reply. Check the PingFederate URL on the app in P0, and that nothing in front of PingFederate answers for /pf-scim.",
      payload: {},
      type: "validation_error",
    });
  }
  return fromNetwork(error) ?? error;
};
