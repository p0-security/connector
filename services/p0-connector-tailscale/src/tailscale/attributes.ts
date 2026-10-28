import {
  type TailnetCall,
  segment,
  tailnetSegment,
  tailscaleRequest,
} from "./api.ts";

/**
 * Device attribute writes (`devices:posture_attributes`). Every key P0
 * writes starts with `custom:p0_`: Tailscale's keys allow only letters,
 * digits, `_` and `:`.
 */

/** The scope every attribute write needs. */
const ATTRIBUTES_SCOPE = "devices:posture_attributes";

/** Tailscale caps an attribute write's audit comment at 200 characters. */
const MAX_COMMENT_LENGTH = 200;

const commentOf = (comment: string): string =>
  comment.slice(0, MAX_COMMENT_LENGTH);

/** `POST /device/{deviceId}/attributes/{key}`: sets one attribute, with an expiry. */
export const setDeviceAttribute = async (
  call: TailnetCall,
  {
    deviceId,
    key,
    value,
    expiry,
    comment,
  }: {
    deviceId: string;
    key: string;
    value: boolean;
    /** RFC 3339. Tailscale removes the attribute a few minutes after it. */
    expiry: string;
    comment: string;
  }
): Promise<void> => {
  const { log, accessToken } = call;
  await tailscaleRequest({
    log,
    method: "POST",
    path: `/api/v2/device/${segment(deviceId)}/attributes/${segment(key)}`,
    accessToken,
    scope: ATTRIBUTES_SCOPE,
    tokenScopes: call.tokenScopes,
    body: { json: { value, expiry, comment: commentOf(comment) } },
  });
};

/** `DELETE /device/{deviceId}/attributes/{key}`. */
export const deleteDeviceAttribute = async (
  call: TailnetCall,
  { deviceId, key }: { deviceId: string; key: string }
): Promise<void> => {
  const { log, accessToken } = call;
  await tailscaleRequest({
    log,
    method: "DELETE",
    path: `/api/v2/device/${segment(deviceId)}/attributes/${segment(key)}`,
    accessToken,
    scope: ATTRIBUTES_SCOPE,
    tokenScopes: call.tokenScopes,
  });
};

/** One device attribute change: set it, with an expiry, or `null` to delete it. */
export type AttributeChange = { value: boolean; expiry: string } | null;

/**
 * `PATCH /tailnet/{tailnet}/device-attributes`: sets and deletes several of
 * one device's attributes in one call (JSON Merge Patch, `null` deletes), so
 * a set and a delete can't be split by a failure between two calls.
 */
export const patchDeviceAttributes = async (
  call: TailnetCall,
  {
    deviceId,
    changes,
    comment,
  }: {
    deviceId: string;
    changes: Record<string, AttributeChange>;
    comment: string;
  }
): Promise<void> => {
  const { log, accessToken } = call;
  await tailscaleRequest({
    log,
    method: "PATCH",
    path: `/api/v2/tailnet/${tailnetSegment(call.tailnet)}/device-attributes`,
    accessToken,
    scope: ATTRIBUTES_SCOPE,
    tokenScopes: call.tokenScopes,
    body: {
      json: { nodes: { [deviceId]: changes }, comment: commentOf(comment) },
    },
  });
};
