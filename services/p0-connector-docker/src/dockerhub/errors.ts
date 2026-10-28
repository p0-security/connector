import {
  ConnectorError,
  type ConnectorErrorType,
  connectorErrorTypeForHttpStatus,
} from "@p0security/connector-core";

import { DockerHubError } from "./api.ts";

/**
 * Docker Hub refused to exchange the organization access token for a JWT:
 * the token is wrong, expired or revoked, or isn't for this org.
 */
export class TokenRejectedError extends Error {
  readonly status: number;

  constructor(status: number) {
    super(`Docker Hub refused the organization access token (${status})`);
    this.name = "TokenRejectedError";
    this.status = status;
  }
}

/** Where a Docker Hub call was aimed, for the messages a failure turns into. */
export type DockerHubTarget = {
  org: string;
  /** The member's username, for a call about one member. */
  username?: string;
};

type AnsweredError = DockerHubError & { status: number };

// Every reading of a Docker Hub status is here, so no caller compares one.
const answered = (error: unknown, statuses: number[]): error is AnsweredError =>
  error instanceof DockerHubError &&
  error.status !== undefined &&
  statuses.includes(error.status);

/** 404: the member or the invite isn't there (any more). */
export const isNotFound = (error: unknown): boolean => answered(error, [404]);

/** 401: Docker Hub no longer takes this JWT. */
export const isUnauthorized = (error: unknown): boolean =>
  answered(error, [401]);

/** 401 or 403: what a token without the scope looks like. */
export const isMissingScope = (error: unknown): boolean =>
  answered(error, [401, 403]);

/** 400 or 409: Docker Hub won't do what the request asks, and says why. */
export const isInvalidRequest = (error: unknown): error is AnsweredError =>
  answered(error, [400, 409]);

/** 400, 401 or 403 from the token exchange: Docker Hub won't take the token. */
export const isTokenRejected = (error: unknown): error is AnsweredError =>
  answered(error, [400, 401, 403]);

/** Docker Hub's reason, or the status when it gave none. */
export const reasonOf = (error: DockerHubError): string =>
  error.dockerMessages.length > 0
    ? error.dockerMessages.join("; ")
    : `HTTP ${error.status ?? "error"}`;

const typeFor = (error: DockerHubError): ConnectorErrorType => {
  if (error.status === undefined) return "upstream_unavailable";
  if (isInvalidRequest(error)) return "validation_error";
  return connectorErrorTypeForHttpStatus(error.status);
};

/**
 * The message P0 shows for a Docker Hub failure. It never quotes
 * {@link DockerHubError}'s own message, whose path can carry an email or an
 * invite id. Only a refusal quotes Docker Hub's reason.
 */
const messageFor = (
  type: ConnectorErrorType,
  error: DockerHubError,
  { org, username }: DockerHubTarget
): string => {
  switch (type) {
    case "insufficient_privileges":
      return `Docker Hub refused the organization access token for ${org} (${error.status}). Check that the token has the Member Edit and Invite Edit scopes for ${org}.`;
    case "object_not_found":
      return `Docker Hub couldn't find ${
        username ? `${username} in ${org}` : org
      }. Check that it still exists, and that the organization access token is for ${org}.`;
    case "rate_limited":
      return `Docker Hub is rate limiting the connector for ${org}. Retry in a few minutes.`;
    case "upstream_unavailable":
      return error.status === undefined
        ? "The connector couldn't reach Docker Hub. Check that it can reach hub.docker.com, then retry."
        : "Docker Hub couldn't answer the connector's request right now. Retry in a few minutes, and check dockerstatus.com if it keeps failing.";
    default:
      return `Docker Hub refused the connector's request for ${org}${
        error.status === undefined ? "" : ` (${error.status})`
      }: ${reasonOf(error)}`;
  }
};

/**
 * Maps a failed Docker Hub call onto the {@link ConnectorError} P0 surfaces.
 * Anything that isn't a Docker Hub failure is returned as is, so a bug stays
 * a bug.
 *
 * | Docker Hub                            | Type                      |
 * | ------------------------------------- | ------------------------- |
 * | the token refused, or any 401 or 403  | `insufficient_privileges` |
 * | 404                                   | `object_not_found`        |
 * | 429                                   | `rate_limited`            |
 * | 5xx, or no answer                     | `upstream_unavailable`    |
 * | 400 or 409                            | `validation_error`        |
 */
export const toConnectorError = (
  error: unknown,
  target: DockerHubTarget
): unknown => {
  const { org, username } = target;
  if (error instanceof ConnectorError) return error;

  if (error instanceof TokenRejectedError) {
    // Never a `validation_error`: the requestor can't fix the token.
    return new ConnectorError({
      type: "insufficient_privileges",
      message: `Docker Hub didn't accept the organization access token for ${org} (${error.status}). Check that the token in the connector's secret was created for ${org}, and that it hasn't expired or been revoked.`,
      payload: { reason: "token_rejected", org, status: error.status },
    });
  }

  if (error instanceof DockerHubError) {
    const type = typeFor(error);
    return new ConnectorError({
      type,
      message: messageFor(type, error, target),
      payload: {
        org,
        // `query` is the field P0 reads off an `object_not_found`.
        ...(type === "object_not_found"
          ? { query: username ? `${org}/${username}` : org }
          : {}),
        ...(error.status !== undefined ? { status: error.status } : {}),
        ...(error.retryAfter !== undefined
          ? { retryAfter: error.retryAfter }
          : {}),
      },
    });
  }

  return error;
};

/** Runs Docker Hub calls, mapping any failure through {@link toConnectorError}. */
export const callDockerHub = async <T>(
  fn: () => Promise<T>,
  target: DockerHubTarget
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    throw toConnectorError(error, target);
  }
};
