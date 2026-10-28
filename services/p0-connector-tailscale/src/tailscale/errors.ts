import {
  ConnectorError,
  type ConnectorErrorType,
  connectorErrorTypeForHttpStatus,
} from "@p0security/connector";

import { TailscaleError } from "./api.ts";
import { covers } from "./scopes.ts";

/**
 * Tailscale refused a token exchange: the client ID or secret is wrong, the
 * client was deleted, it lacks a scope that was asked for, or the federated
 * identity doesn't trust the connector's cloud identity.
 */
export class TokenRejectedError extends Error {
  readonly status: number;
  /** Tailscale's reason, with secrets cut out. */
  readonly reason: string;
  /** The scopes the exchange asked for, or none for every scope the credential holds. */
  readonly scopes: readonly string[];

  constructor(status: number, reason: string, scopes: readonly string[] = []) {
    super(
      `Tailscale refused the connector's credential (${status}): ${reason}`
    );
    this.name = "TokenRejectedError";
    this.status = status;
    this.reason = reason;
    this.scopes = scopes;
  }
}

/**
 * Whether Tailscale refused an exchange because the OAuth client doesn't
 * hold a scope it asked for. Tailscale answers that with 403 `OAuth client
 * cannot grant scopes "..."`, and an OAuth server can answer it with 400.
 */
export const isScopeRefusal = (error: unknown): error is TokenRejectedError =>
  error instanceof TokenRejectedError &&
  error.scopes.length > 0 &&
  (error.status === 400 ||
    (error.status === 403 && /cannot grant scopes/i.test(error.reason)));

/** Where a Tailscale call was aimed, for the messages a failure turns into. */
export type TailscaleTarget = {
  tailnet: string;
  /** What the call was about, such as `device n123` or `the policy file`. */
  subject?: string;
  /**
   * False when the subject can be missing while the tailnet is fine, such
   * as one device, so a 404 doesn't point at the Tailnet ID.
   */
  missingMeansTailnet?: boolean;
};

type AnsweredError = TailscaleError & { status: number };

// Every reading of a Tailscale status is here, so no caller compares one.
const answered = (error: unknown, statuses: number[]): error is AnsweredError =>
  error instanceof TailscaleError &&
  error.status !== undefined &&
  statuses.includes(error.status);

/**
 * What the failed call's token says about the scope the call needs: held,
 * lacking, or unknown when Tailscale didn't say which scopes the token
 * carries.
 */
const scopeOf = (error: TailscaleError): "held" | "lacking" | "unknown" =>
  error.scope === undefined || error.tokenScopes === undefined
    ? "unknown"
    : covers(error.tokenScopes, error.scope)
      ? "held"
      : "lacking";

/**
 * 404 to a token known to lack the call's scope. Tailscale answers a
 * missing scope with 404 "not found", not 403.
 */
export const lacksScope = (error: unknown): error is AnsweredError =>
  answered(error, [404]) && scopeOf(error) === "lacking";

/**
 * 404: what the call was about isn't there (any more), unless the token is
 * known to lack the call's scope. When the token's scopes aren't known, it
 * may still be the scope: {@link notFoundHint} says so.
 */
export const isNotFound = (error: unknown): boolean =>
  answered(error, [404]) && !lacksScope(error);

/** Any 404, whether what the call was about is missing or the token lacks its scope. */
export const isAnyNotFound = (error: unknown): boolean =>
  answered(error, [404]);

/**
 * For a 404 whose token's scopes aren't known, a sentence saying the
 * credential may lack the call's scope, since Tailscale answers that with
 * "not found" too. Empty for any other failure.
 */
export const notFoundHint = (error: unknown): string =>
  answered(error, [404]) && scopeOf(error) === "unknown"
    ? ` Tailscale also answers "not found" when the connector's Tailscale credential lacks the scope a call needs, so check that it holds ${
        error.scope ?? "every scope P0 needs"
      }.`
    : "";

/** 401: Tailscale no longer takes this access token. */
export const isUnauthorized = (error: unknown): boolean =>
  answered(error, [401]);

/**
 * 403: Tailscale refused the call. A token that lacks the call's scope is
 * mostly answered with 404 instead ({@link lacksScope}).
 */
export const isForbidden = (error: unknown): boolean => answered(error, [403]);

/**
 * 400, 402 or 403 to a device attribute write: for a device that's on the
 * tailnet, its plan doesn't allow custom attributes, or the credential
 * can't set them. Tailscale's answer doesn't say which.
 */
export const isAttributeRefusal = (error: unknown): error is AnsweredError =>
  answered(error, [400, 402, 403]);

/**
 * What P0 says about an {@link isAttributeRefusal}, at install and at grant.
 * Tailscale's reason is quoted when it gives one, since a 400 can be the
 * request itself and not the plan.
 */
export const attributeRefusalMessage = (
  tailnet: string,
  error: AnsweredError
) => {
  const reason =
    error.tailscaleMessage !== undefined && error.tailscaleMessage !== ""
      ? `: ${reasonOf(error)}`
      : "";
  return `Tailnet ${tailnet} refused a custom device attribute (${error.status})${reason}. P0 sets posture attributes, which need a Premium or Enterprise plan, and a credential with devices:posture_attributes.`;
};

/** 400, 401 or 403 from a token exchange: Tailscale won't take the credential. */
export const isTokenRejected = (error: unknown): error is AnsweredError =>
  answered(error, [400, 401, 403]);

/** Tailscale's reason, or the status when it gave none, without a closing full stop. */
export const reasonOf = (error: TailscaleError): string =>
  error.tailscaleMessage !== undefined && error.tailscaleMessage !== ""
    ? error.tailscaleMessage.replace(/\.$/, "")
    : `HTTP ${error.status ?? "error"}`;

const typeFor = (error: TailscaleError): ConnectorErrorType => {
  const { status } = error;
  if (status === undefined) return "upstream_unavailable";
  // 400 is Tailscale refusing the change, and 402 is the tailnet's plan.
  // Neither is retried.
  if (status === 400 || status === 402 || status === 409) {
    return "validation_error";
  }
  if (lacksScope(error)) return "insufficient_privileges";
  return connectorErrorTypeForHttpStatus(status);
};

/**
 * The message P0 shows for a Tailscale failure. It never quotes
 * {@link TailscaleError}'s own message, whose path can carry a device id.
 * Only a refusal quotes Tailscale's reason.
 */
const messageFor = (
  type: ConnectorErrorType,
  error: TailscaleError,
  { tailnet, subject, missingMeansTailnet = true }: TailscaleTarget
): string => {
  switch (type) {
    case "insufficient_privileges":
      if (lacksScope(error)) {
        return `The connector's Tailscale credential for tailnet ${tailnet} lacks ${error.scope}, which P0 needs for ${subject ?? "this call"} (Tailscale answered "not found"). Add ${error.scope} to the credential, then retry.`;
      }
      return `Tailscale tailnet ${tailnet} refused the connector's request (${error.status}). Check that the connector's Tailscale credential holds every scope P0 needs.`;
    case "object_not_found":
      return `Tailscale tailnet ${tailnet} couldn't find ${subject ?? "what the connector asked for"}.${notFoundHint(error)}${
        missingMeansTailnet
          ? " Check that the tailnet still exists. The Tailnet ID can't be changed in place: if it's wrong, remove this tailnet from P0 and add it again with the right one."
          : ""
      }`;
    case "rate_limited":
      return `Tailscale is rate limiting the connector on tailnet ${tailnet}. Retry in ${
        error.retryAfter === undefined
          ? "a few minutes"
          : `${error.retryAfter} seconds`
      }.`;
    case "upstream_unavailable":
      if (error.status === undefined) {
        return "The connector couldn't reach api.tailscale.com. Check that it can reach the Tailscale API, then retry.";
      }
      return "Tailscale couldn't answer the connector's request right now. Retry in a few minutes, and check status.tailscale.com if it keeps failing.";
    case "validation_error":
      if (error.status === 402) {
        return `Tailscale tailnet ${tailnet}'s plan doesn't allow this (402): ${reasonOf(error)}. P0 sets posture attributes, which need a Premium or Enterprise plan.`;
      }
      return `Tailscale tailnet ${tailnet} refused the change (${error.status}): ${reasonOf(error)}`;
    default:
      return `Tailscale tailnet ${tailnet} refused the connector's request${
        error.status === undefined ? "" : ` (${error.status})`
      }.`;
  }
};

/**
 * Maps a failed Tailscale call onto the {@link ConnectorError} P0 surfaces.
 * Anything that isn't a Tailscale failure is returned as is, so a bug stays
 * a bug. A 429 goes back to P0 with `retryAfter`.
 *
 * | Tailscale                                  | Type                      |
 * | ------------------------------------------ | ------------------------- |
 * | the credential refused, or a 401 or 403    | `insufficient_privileges` |
 * | 404 to a token known to lack the scope     | `insufficient_privileges` |
 * | any other 404                              | `object_not_found`        |
 * | 429                                        | `rate_limited`            |
 * | 5xx, or no answer                          | `upstream_unavailable`    |
 * | 400, 402 or 409                            | `validation_error`        |
 */
export const toConnectorError = (
  error: unknown,
  target: TailscaleTarget
): unknown => {
  const { tailnet, subject } = target;
  if (error instanceof ConnectorError) return error;

  if (isScopeRefusal(error)) {
    const scopes = error.scopes.join(", ");
    return new ConnectorError({
      type: "insufficient_privileges",
      message: `Tailscale won't give the connector a token with ${scopes} for tailnet ${tailnet} (${error.status}): ${error.reason}. The connector's OAuth client lacks at least one of these scopes. Add the missing ones to it, then retry.`,
      payload: {
        reason: "scopes_refused",
        tailnet,
        status: error.status,
        scopes: error.scopes.join(" "),
      },
    });
  }

  if (error instanceof TokenRejectedError) {
    // Never a `validation_error`: the requestor can't fix the credential.
    return new ConnectorError({
      type: "insufficient_privileges",
      message: `Tailscale didn't accept the connector's credential for tailnet ${tailnet} (${error.status}): ${error.reason}. Check the OAuth client's secret or the federated identity's trust, and that it holds the scopes P0 needs. The client ID can't be changed in place: if it's wrong, remove this tailnet from P0 and add it again with the right one.`,
      payload: { reason: "token_rejected", tailnet, status: error.status },
    });
  }

  if (error instanceof TailscaleError) {
    const type = typeFor(error);
    return new ConnectorError({
      type,
      message: messageFor(type, error, target),
      payload: {
        tailnet,
        // `query` is the field P0 reads off an `object_not_found`.
        ...(type === "object_not_found" ? { query: subject ?? tailnet } : {}),
        ...(lacksScope(error) ? { missing: error.scope } : {}),
        ...(error.status !== undefined ? { status: error.status } : {}),
        ...(error.retryAfter !== undefined
          ? { retryAfter: error.retryAfter }
          : {}),
      },
    });
  }

  return error;
};

/** Runs Tailscale calls, mapping any failure through {@link toConnectorError}. */
export const callTailscale = async <T>(
  fn: () => Promise<T>,
  target: TailscaleTarget
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    throw toConnectorError(error, target);
  }
};
