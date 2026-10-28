import {
  ConnectorError,
  type ConnectorErrorType,
  connectorErrorTypeForHttpStatus,
} from "@p0security/connector";

import { Auth0Error } from "./api.ts";

/**
 * The tenant refused the client-credentials exchange: the client id or secret
 * is wrong, the client was deleted, or it isn't authorized for the Management
 * API.
 */
export class TokenRejectedError extends Error {
  readonly status: number;
  /** Auth0's reason, with the client secret cut out. */
  readonly reason: string;

  constructor(status: number, reason: string) {
    super(`Auth0 refused the client credentials (${status}): ${reason}`);
    this.name = "TokenRejectedError";
    this.status = status;
    this.reason = reason;
  }
}

/** Where an Auth0 call was aimed, for the messages a failure turns into. */
export type Auth0Target = {
  tenant: string;
  /** What the call was about, such as `user auth0|123` or `role rol_abc`. */
  subject?: string;
};

type AnsweredError = Auth0Error & { status: number };

// Every reading of an Auth0 status is here, so no caller compares one.
const answered = (error: unknown, statuses: number[]): error is AnsweredError =>
  error instanceof Auth0Error &&
  error.status !== undefined &&
  statuses.includes(error.status);

/** 404: what the call was about isn't there (any more). */
export const isNotFound = (error: unknown): boolean => answered(error, [404]);

/** 401: the tenant no longer takes this access token. */
export const isUnauthorized = (error: unknown): boolean =>
  answered(error, [401]);

/** 409: what the call asked for already holds, or can't be added again. */
export const isConflict = (error: unknown): error is AnsweredError =>
  answered(error, [409]);

/**
 * 409, or a 400 that says so: what a grant asked to add is already there.
 * Auth0 doesn't document either for a role or permission that's already
 * assigned, so both are taken, and nothing else is.
 */
export const isAlreadyAssigned = (error: unknown): boolean =>
  answered(error, [409]) ||
  (answered(error, [400]) &&
    error.auth0Messages.some((message) => /already/i.test(message)));

/** 400 or 409: Auth0 won't do what the request asks, and says why. */
export const isInvalidRequest = (error: unknown): error is AnsweredError =>
  answered(error, [400, 409]);

/** 400, 401 or 403 from the token exchange: the tenant won't take the client credentials. */
export const isTokenRejected = (error: unknown): error is AnsweredError =>
  answered(error, [400, 401, 403]);

/** Auth0's reason, or the status when it gave none, without a closing full stop. */
export const reasonOf = (error: Auth0Error): string =>
  error.auth0Messages.length > 0
    ? error.auth0Messages.join("; ").replace(/\.$/, "")
    : `HTTP ${error.status ?? "error"}`;

const typeFor = (error: Auth0Error): ConnectorErrorType => {
  if (error.status === undefined) return "upstream_unavailable";
  if (isInvalidRequest(error)) return "validation_error";
  return connectorErrorTypeForHttpStatus(error.status);
};

/**
 * The message P0 shows for an Auth0 failure. It never quotes
 * {@link Auth0Error}'s own message, whose path can carry a user id. Only a
 * refusal and a missing scope quote Auth0's reason.
 */
const messageFor = (
  type: ConnectorErrorType,
  error: Auth0Error,
  { tenant, subject }: Auth0Target
): string => {
  switch (type) {
    case "insufficient_privileges":
      return `Auth0 tenant ${tenant} refused the connector's request (${error.status}): ${reasonOf(error)}. Check that the connector's Management API application is authorized with every scope P0 needs.`;
    case "object_not_found":
      return `Auth0 tenant ${tenant} couldn't find ${subject ?? "what the connector asked for"}. Check that it still exists.`;
    case "rate_limited":
      return `Auth0 tenant ${tenant} is rate limiting the connector. Retry in ${
        error.retryAfter === undefined
          ? "a few minutes"
          : `${error.retryAfter} seconds`
      }.`;
    case "upstream_unavailable":
      return error.status === undefined
        ? `The connector couldn't reach Auth0 tenant ${tenant}. Check that it can reach ${tenant}, then retry.`
        : "Auth0 couldn't answer the connector's request right now. Retry in a few minutes, and check status.auth0.com if it keeps failing.";
    default:
      return `Auth0 tenant ${tenant} refused the connector's request${
        error.status === undefined ? "" : ` (${error.status})`
      }: ${reasonOf(error)}`;
  }
};

/**
 * Maps a failed Auth0 call onto the {@link ConnectorError} P0 surfaces.
 * Anything that isn't an Auth0 failure is returned as is, so a bug stays a
 * bug. A 429 gets here once `auth0Request` has stopped retrying it, and goes
 * back to P0 with `retryAfter`.
 *
 * | Auth0                                     | Type                      |
 * | ----------------------------------------- | ------------------------- |
 * | the credentials refused, or a 401 or 403  | `insufficient_privileges` |
 * | 404                                       | `object_not_found`        |
 * | 429                                       | `rate_limited`            |
 * | 5xx, or no answer                         | `upstream_unavailable`    |
 * | 400 or 409                                | `validation_error`        |
 */
export const toConnectorError = (
  error: unknown,
  target: Auth0Target
): unknown => {
  const { tenant, subject } = target;
  if (error instanceof ConnectorError) return error;

  if (error instanceof TokenRejectedError) {
    // Never a `validation_error`: the requestor can't fix the credentials.
    return new ConnectorError({
      type: "insufficient_privileges",
      message: `Auth0 tenant ${tenant} didn't accept the connector's client credentials (${error.status}): ${error.reason}. Check the client id in the P0 install and the client secret in the connector's secret, and that the application is authorized for the Auth0 Management API.`,
      payload: { reason: "token_rejected", tenant, status: error.status },
    });
  }

  if (error instanceof Auth0Error) {
    const type = typeFor(error);
    return new ConnectorError({
      type,
      message: messageFor(type, error, target),
      payload: {
        tenant,
        // `query` is the field P0 reads off an `object_not_found`.
        ...(type === "object_not_found" ? { query: subject ?? tenant } : {}),
        ...(error.status !== undefined ? { status: error.status } : {}),
        ...(error.errorCode !== undefined
          ? { errorCode: error.errorCode }
          : {}),
        ...(error.retryAfter !== undefined
          ? { retryAfter: error.retryAfter }
          : {}),
      },
    });
  }

  return error;
};

/** Runs Auth0 calls, mapping any failure through {@link toConnectorError}. */
export const callAuth0 = async <T>(
  fn: () => Promise<T>,
  target: Auth0Target
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    throw toConnectorError(error, target);
  }
};
