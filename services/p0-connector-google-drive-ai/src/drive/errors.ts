import type { ConnectorErrorType } from "@p0security/connector-core";
import { ConnectorError } from "@p0security/connector-core";

/** Contextual fields attached to every {@link ConnectorError} this module raises. */
type DriveErrorPayload = Record<string, boolean | number | string>;

/**
 * The HTTP status behind a googleapis failure, or `undefined` when the call
 * never reached Google at all.
 *
 * Three shapes, because the status lands in a different place depending on how
 * deep the failure happened: `code` on a Gaxios error, `status` on some
 * transport errors, and `response.status` when only the raw response survives.
 */
export const statusOf = (error: any): number | undefined =>
  error?.code ?? error?.status ?? error?.response?.status;

const reasonsOf = (error: any): string[] => {
  const errors = error?.errors ?? error?.response?.data?.error?.errors;
  if (!Array.isArray(errors)) return [];
  return errors.map((entry: any) => String(entry?.reason ?? ""));
};

const messageOf = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

const markers = (error: unknown): string =>
  [...reasonsOf(error), messageOf(error)].join(" ");

/** Drive throttling, which arrives as a 403 whose reason names a rate limit
 * (`sharingRateLimitExceeded`, `userRateLimitExceeded`) as often as it arrives
 * as a 429. Checked before the ceiling below, because both say "limit". */
const isRateLimited = (error: unknown): boolean => {
  const status = statusOf(error);
  if (status === 429) return true;
  return status === 403 && /rate\s*limit/i.test(markers(error));
};

/**
 * Whether Drive refused the write because the item has reached its ceiling on
 * individually-named principals.
 *
 * Google documents a per-item cap but not the error code raised at it, and the
 * documented figure is unmeasured — so this matches on the presence of a limit
 * marker rather than on an exact reason string, and no number is hard-coded
 * anywhere. A miss degrades to the generic 403 mapping, which is the safe
 * direction: a wrong guess costs a less specific error, never a wrong grant.
 */
const isPermissionCeiling = (error: unknown): boolean =>
  statusOf(error) === 403 && /limit|maximum/i.test(markers(error));

const CEILING_MESSAGE =
  "Google Drive refused the permission because this item has reached its limit " +
  "on individually-shared principals. The usual cause is residue: entries left " +
  "behind by grants whose revoke did not complete. Clear stale entries from the " +
  "item's sharing list and retry.";

const FORBIDDEN_MESSAGE =
  "Google Drive refused the request. This connector's service identity must be " +
  "an organizer on the shared drive holding this item.";

/**
 * Maps a Drive v3 failure onto a categorized {@link ConnectorError}.
 *
 * `payload` should carry the ids the operator needs to find the item; for
 * `object_not_found` the convention is `query`, which is the field P0 surfaces.
 */
export const mapDriveError = (
  error: unknown,
  payload: DriveErrorPayload
): ConnectorError => {
  if (error instanceof ConnectorError) return error;

  if (isRateLimited(error)) {
    return new ConnectorError({
      type: "rate_limited",
      message: messageOf(error),
      payload,
      cause: error,
    });
  }
  if (isPermissionCeiling(error)) {
    return new ConnectorError({
      type: "validation_error",
      message: CEILING_MESSAGE,
      payload,
      cause: error,
    });
  }

  const status = statusOf(error);
  const type: ConnectorErrorType =
    status === 404
      ? "object_not_found"
      : status === 403 || status === 401
        ? "insufficient_privileges"
        : status !== undefined && status >= 500
          ? "upstream_unavailable"
          : "unknown";

  return new ConnectorError({
    type,
    message:
      type === "insufficient_privileges" ? FORBIDDEN_MESSAGE : messageOf(error),
    payload,
    cause: error,
  });
};

/** Runs a Drive call, mapping any failure onto a categorized error. */
export const callDrive = async <T>(
  fn: () => Promise<T>,
  payload: DriveErrorPayload
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    throw mapDriveError(error, payload);
  }
};
