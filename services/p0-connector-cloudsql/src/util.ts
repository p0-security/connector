import {
  ConnectorError,
  type ConnectorErrorType,
  connectorErrorTypeForHttpStatus,
} from "@p0security/connector-core";
import { GaxiosError } from "gaxios";

/**
 * Maps a `verifyMember` error to a categorized {@link ConnectorError} so
 * eligibility decisions surface as clean HTTP statuses, not opaque 500s. Keys
 * off the sp-shared error's `type` discriminant: "validate" (policy denial) and
 * "proxy" (GCP lookup failure).
 */
export const mapMemberVerificationError = (error: unknown): ConnectorError => {
  const type =
    error instanceof Error && "type" in error ? error.type : undefined;
  if (type === "validate") {
    return new ConnectorError({
      type: "validation_error",
      message: error instanceof Error ? error.message : String(error),
      payload: {},
      cause: error,
    });
  }
  if (type === "proxy") {
    return new ConnectorError({
      type: "upstream_unavailable",
      message: "Failed to verify member eligibility.",
      payload: {},
      cause: error,
    });
  }
  return new ConnectorError({
    type: "unknown",
    message: "Failed to verify member eligibility.",
    payload: {},
    cause: error,
  });
};

/**
 * Memoizes an async factory, caching the resolved value and coalescing
 * concurrent callers onto one in-flight promise. A rejected promise is evicted
 * so a transient cold-start failure can be retried.
 */
export const memoizeAsync = <T>(
  factory: () => Promise<T>
): (() => Promise<T>) => {
  let promise: Promise<T> | undefined;
  return () =>
    (promise ??= factory().catch((error) => {
      promise = undefined;
      throw error;
    }));
};

// SQL Admin HTTP status -> ConnectorError type; unlisted falls back to the
// framework's mapping.
const SQL_ADMIN_ERROR_TYPE: Record<number, ConnectorErrorType> = {
  400: "validation_error",
  409: "already_exists",
  403: "insufficient_privileges",
  404: "object_not_found",
  429: "rate_limited",
};

/**
 * Maps a SQL Admin API failure to a categorized {@link ConnectorError} so the
 * control plane gets an actionable type rather than an opaque 500.
 *
 * The status and the API's own message go in the error, because the control
 * plane only sees the error the connector sends back, not its `cause`.
 */
export const mapSqlAdminError = (error: unknown, email: string) => {
  const gaxiosError = error instanceof GaxiosError ? error : undefined;
  // Categorize off the HTTP status, not `error.code`: gaxios sets `code` to a
  // system string (e.g. "ECONNRESET") for transport failures. A missing status
  // means the API was never reached (transport failure) -> upstream_unavailable.
  const httpStatus = gaxiosError?.status ?? gaxiosError?.response?.status;
  const type: ConnectorErrorType = !gaxiosError
    ? "unknown"
    : httpStatus === undefined
      ? "upstream_unavailable"
      : (SQL_ADMIN_ERROR_TYPE[httpStatus] ??
        connectorErrorTypeForHttpStatus(httpStatus));
  const status = httpStatus === undefined ? "" : ` (${httpStatus})`;
  const reason = error instanceof Error ? error.message : String(error);
  return new ConnectorError({
    type,
    message: `CloudSQL API request failed for user '${email}'${status}: ${reason}`,
    payload:
      httpStatus === undefined ? { email } : { email, status: httpStatus },
    cause: error,
  });
};
