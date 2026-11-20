import {
  ConnectorError,
  type ConnectorErrorOptions,
} from "@p0security/connector-core";

// copied from services/p0-connector-redshift-ai/src/redshift/data-api.ts,
// with SSM's error names
const SDK_ERROR_TYPES: Record<string, ConnectorErrorOptions["type"]> = {
  AccessDeniedException: "insufficient_privileges",
  ThrottlingException: "rate_limited",
  InternalServerError: "upstream_unavailable",
};

/** The name an SDK error carries, or `undefined` for anything else. */
export const nameOf = (error: unknown) =>
  error instanceof Error ? error.name : undefined;

export const isNamed = (error: unknown, name: string): error is Error =>
  nameOf(error) === name;

/**
 * What P0 shows for an SSM failure. AWS's message for a refused call names
 * the role and the action. Any other message can quote the request, which
 * holds the script, so only a refusal keeps it.
 */
const messageFor = (
  type: ConnectorErrorOptions["type"] | undefined,
  error: unknown
) => {
  if (type === "insufficient_privileges") {
    const refusal = error instanceof Error ? error.message : "";
    return `SSM refused the connector's role${refusal ? `: ${refusal.replace(/\.$/, "")}` : ""}. Check the role's SSM permissions.`;
  }
  if (type === "rate_limited") {
    return "SSM throttled the connector. Try again in a moment.";
  }
  return `SSM failed the call (${nameOf(error) ?? "unknown error"}). Try again, and contact P0 support if it keeps failing.`;
};

/**
 * Maps an SSM failure to the error P0 shows, with the AWS error's name. Most
 * errors outside the names above come from the network or from SSM, such as
 * a timeout or a reset socket, so they count as SSM being unavailable, not
 * as P0's bug.
 */
export const toConnectorError = (error: unknown): ConnectorError => {
  if (error instanceof ConnectorError) return error;
  const name = nameOf(error);
  const type = name ? SDK_ERROR_TYPES[name] : undefined;
  return new ConnectorError({
    type: type ?? "upstream_unavailable",
    message: messageFor(type, error),
    payload: name ? { awsError: name } : {},
  });
};
