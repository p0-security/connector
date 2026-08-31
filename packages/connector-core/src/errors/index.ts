import { TRPCClientError } from "@trpc/client";
import type { TRPCDefaultErrorShape } from "@trpc/server";
import { TRPCError } from "@trpc/server";
import { z } from "zod/v4";

/**
 * The enumerable set of abstract error categories that a connector may emit.
 *
 * - `insufficient_privileges`: The identity the connector is acting as (e.g.
 *   `p0_iam_manager` for a database, a service account for a cloud IAM API)
 *   does not have the permissions required to perform the requested operation.
 *   Resolution typically involves granting additional privileges to that
 *   identity.
 *
 * - `object_not_found`: A resource referenced by the operation (a role, user,
 *   schema, table, project, etc.) does not exist on the target system.
 *   Resolution typically involves creating the missing resource or correcting
 *   the reference.
 *
 * - `dependency_violation`: The operation cannot be completed because of
 *   constraints on the target system — e.g. dropping a role that still owns
 *   objects, removing a policy that other resources depend on. Resolution
 *   typically involves clearing the dependency before retrying.
 *
 * - `already_exists`: The operation cannot be completed because a resource
 *   with the same identity already exists on the target system — e.g.
 *   creating a role or user that is already present. Resolution typically
 *   involves choosing a different name or reusing the existing resource.
 *
 * - `upstream_unavailable`: The connector could not reach or communicate with
 *   the target system at all — e.g. network failure, DNS resolution failure,
 *   connection refused, the database is down for maintenance. Distinct from
 *   `insufficient_privileges`, where the upstream is reachable and explicitly
 *   rejects the operation. Resolution typically involves checking the
 *   connector's network path to the target system.
 *
 * - `rate_limited`: The upstream system is throttling the connector or a
 *   service quota has been exceeded. Resolution typically involves backing
 *   off and retrying, or requesting a quota increase from the upstream
 *   provider.
 *
 * - `validation_error`: The requested operation was rejected because its
 *   inputs were malformed or failed validation — e.g. a required field is
 *   missing, a value is out of range, or an identifier does not conform to the
 *   expected format. The request never reached, or was refused before acting
 *   on, the target system. Resolution typically involves correcting the
 *   request inputs and retrying.
 *
 * - `unknown`: A catch-all for failures that don't map cleanly to one of the
 *   categories above. Used when the connector cannot confidently classify the
 *   underlying error. The accompanying `responseMessage` should provide
 *   generic troubleshooting guidance.
 */
const ConnectorErrorTypeSchema = z.enum([
  "insufficient_privileges",
  "object_not_found",
  "dependency_violation",
  "already_exists",
  "upstream_unavailable",
  "rate_limited",
  "validation_error",
  "unknown",
]);

export type ConnectorErrorType = z.infer<typeof ConnectorErrorTypeSchema>;

/**
 * Wire shape of a {@link ConnectorError} after serialization.
 */
export const ConnectorErrorDataSchema = z.object({
  type: ConnectorErrorTypeSchema,
  payload: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])),
  message: z.string(),
  path: z.string().optional(),
  stack: z.string().optional(),
});

export type ConnectorErrorData = z.infer<typeof ConnectorErrorDataSchema>;

export type ConnectorErrorOptions = {
  /** The abstract connector error type that occurred */
  type: ConnectorErrorType;
  /** Will be surfaced to end users and can be used for actionable instructions */
  message: string;
  /** Parametrized contextual data associated with this connector error */
  payload: ConnectorErrorData["payload"];
  cause?: unknown;
};

type TRPCErrorCode = ConstructorParameters<typeof TRPCError>[0]["code"];

/**
 * Maps each abstract {@link ConnectorErrorType} to the tRPC error code that
 * best reflects its HTTP semantics. Because `ConnectorError` extends
 * `TRPCError`, this code drives the HTTP status of the response automatically.
 */
const connectorErrorTRPCCode = (type: ConnectorErrorType): TRPCErrorCode => {
  switch (type) {
    case "insufficient_privileges":
      // 403: At this hop, the connector's identity was denied by the upstream.
      // Non-retryable, no page. The backend translates this into a
      // customer-facing BadInstallationError (422) further up the stack —
      // the codes intentionally differ because the two hops answer
      // different questions for different consumers.
      return "FORBIDDEN";
    case "object_not_found":
      return "NOT_FOUND";
    case "dependency_violation":
    case "already_exists":
      return "CONFLICT";
    case "upstream_unavailable":
      // 503: The upstream system was unreachable or unable to respond.
      return "SERVICE_UNAVAILABLE";
    case "rate_limited":
      return "TOO_MANY_REQUESTS";
    case "unknown":
      return "INTERNAL_SERVER_ERROR";
    case "validation_error":
      return "PRECONDITION_FAILED";
  }
};

/**
 * Thrown by connector implementations to signal an expected, categorized
 * failure. Extends `TRPCError` so that the HTTP status of the response
 * reflects the abstract error type without any extra middleware.
 */
export class ConnectorError extends TRPCError {
  readonly data: ConnectorErrorData;

  constructor(opts: ConnectorErrorOptions) {
    super({
      code: connectorErrorTRPCCode(opts.type),
      message: opts.message,
      cause: opts.cause,
    });
    this.name = "ConnectorError";
    this.data = {
      type: opts.type,
      message: opts.message,
      payload: opts.payload,
    };
  }

  toData() {
    return this.data;
  }
}

/**
 * Extracts the data from a connector error on the client-side
 *
 * @returns the connector error's data
 */
export const extractConnectorErrorData = (
  error: unknown
): ConnectorErrorData | null => {
  if (!(error instanceof TRPCClientError)) return null;
  const result = ConnectorErrorDataSchema.safeParse(error.data);
  if (!result.success) return null;
  return result.data;
};

/**
 * Shared `errorFormatter` for use with `initTRPC.create({ errorFormatter })`.
 *
 * Adds ConnectorError-specific data into the response body. The HTTP status
 * of the response is set by the underlying `TRPCError.code` and does
 * not need to be handled here.
 *
 * Errors not originating from a {@link ConnectorError} pass through unchanged.
 */
export const connectorErrorFormatter = ({
  shape,
  error,
}: {
  shape: TRPCDefaultErrorShape;
  error: TRPCError;
}) => {
  if (error instanceof ConnectorError) {
    return {
      ...shape,
      data: {
        ...shape.data,
        ...error.toData(),
      },
    };
  }

  // Two cases reach this branch:
  //
  // 1. The procedure threw a TRPCError directly (not a ConnectorError) —
  //    its code/status are whatever the thrower set; the default shape is
  //    passed through unchanged.
  //
  // 2. The procedure threw something that isn't a TRPCError at all —
  //    tRPC has already wrapped it as TRPCError(INTERNAL_SERVER_ERROR)
  //    before this formatter runs, so the response is a 500.
  return shape;
};

/** Maps a HTTP status to the abstract {@link ConnectorErrorType} the framework surfaces to users. */
export const connectorErrorTypeForHttpStatus = (
  status: number
): ConnectorErrorType => {
  if (status === 401 || status === 403) return "insufficient_privileges";
  if (status === 404) return "object_not_found";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "upstream_unavailable";
  return "unknown";
};
