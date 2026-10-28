import { z } from "zod";

import {
  type TailnetCall,
  parseResponse,
  segment,
  tailnetSegment,
  tailscaleRequest,
} from "./api.ts";

/**
 * The tailnet reads the connector makes, in the shapes Tailscale's OpenAPI
 * spec gives. None of them paginates: Tailscale returns every result at once.
 */

const user = z.object({
  id: z.string(),
  loginName: z.string(),
  displayName: z.string().optional(),
  type: z.string().optional(),
  role: z.string().optional(),
  status: z.string().optional(),
});

export type TailscaleUser = z.infer<typeof user>;

const device = z.object({
  id: z.string().optional(),
  nodeId: z.string(),
  name: z.string().optional(),
  hostname: z.string().optional(),
  /** Who registered the device. Its owner only when the device has no tags. */
  user: z.string().optional(),
  tags: z.array(z.string()).optional(),
  /** True for a device another tailnet shares in, whose `name` is in that tailnet's domain. */
  isExternal: z.boolean().optional(),
});

export type TailscaleDevice = z.infer<typeof device>;

const service = z.object({
  /** Already carries the `svc:` prefix. */
  name: z.string(),
});

export type TailscaleService = z.infer<typeof service>;

const routes = z.object({
  advertisedRoutes: z.array(z.string()).nullish(),
  enabledRoutes: z.array(z.string()).nullish(),
});

const attributes = z.object({
  attributes: z
    .record(z.string(), z.union([z.string(), z.number(), z.boolean()]))
    .nullish(),
  expiries: z.record(z.string(), z.string()).nullish(),
});

export type DeviceAttributes = {
  attributes: Record<string, boolean | number | string>;
  expiries: Record<string, string>;
};

/** A GET of `path`, which needs `scope`, read with `schema`. */
const get = async <T>(
  call: TailnetCall,
  path: string,
  schema: z.ZodType<T>,
  what: string,
  scope: string
): Promise<T> => {
  const { log, accessToken, tokenScopes } = call;
  const { data } = await tailscaleRequest({
    log,
    method: "GET",
    path,
    accessToken,
    scope,
    tokenScopes,
  });
  return parseResponse({ log, schema, data, what });
};

const tailnetPath = (call: TailnetCall, rest: string): string =>
  `/api/v2/tailnet/${tailnetSegment(call.tailnet)}${rest}`;

/** `GET /tailnet/{tailnet}/users` (`users:read`): the tailnet's members. */
export const listUsers = async (call: TailnetCall): Promise<TailscaleUser[]> =>
  (
    await get(
      call,
      tailnetPath(call, "/users"),
      z.object({ users: z.array(user).nullish() }),
      "the tailnet's users",
      "users:read"
    )
  ).users ?? [];

/**
 * `GET /tailnet/{tailnet}/devices` (`devices:core:read`): every device, in
 * Tailscale's default fields, which carry `tags` and `isExternal`.
 */
export const listDevices = async (
  call: TailnetCall
): Promise<TailscaleDevice[]> =>
  (
    await get(
      call,
      tailnetPath(call, "/devices"),
      z.object({ devices: z.array(device).nullish() }),
      "the tailnet's devices",
      "devices:core:read"
    )
  ).devices ?? [];

/** `GET /device/{deviceId}` (`devices:core:read`). */
export const getDevice = (
  call: TailnetCall,
  deviceId: string
): Promise<TailscaleDevice> =>
  get(
    call,
    `/api/v2/device/${segment(deviceId)}`,
    device,
    "a device",
    "devices:core:read"
  );

/** `GET /device/{deviceId}/routes` (`devices:routes:read`). */
export const getDeviceRoutes = async (
  call: TailnetCall,
  deviceId: string
): Promise<{ advertisedRoutes: string[]; enabledRoutes: string[] }> => {
  const { advertisedRoutes, enabledRoutes } = await get(
    call,
    `/api/v2/device/${segment(deviceId)}/routes`,
    routes,
    "a device's routes",
    "devices:routes:read"
  );
  return {
    advertisedRoutes: advertisedRoutes ?? [],
    enabledRoutes: enabledRoutes ?? [],
  };
};

/**
 * `GET /device/{deviceId}/attributes` (`devices:posture_attributes:read`):
 * every attribute, the customer's and Tailscale's own included.
 */
export const getDeviceAttributes = async (
  call: TailnetCall,
  deviceId: string
): Promise<DeviceAttributes> => {
  const read = await get(
    call,
    `/api/v2/device/${segment(deviceId)}/attributes`,
    attributes,
    "a device's attributes",
    "devices:posture_attributes:read"
  );
  return { attributes: read.attributes ?? {}, expiries: read.expiries ?? {} };
};

/** `GET /tailnet/{tailnet}/services` (`services:read`). */
export const listServices = async (
  call: TailnetCall
): Promise<TailscaleService[]> =>
  (
    await get(
      call,
      tailnetPath(call, "/services"),
      z.object({ vipServices: z.array(service).nullish() }),
      "the tailnet's services",
      "services:read"
    )
  ).vipServices ?? [];

/**
 * `GET /tailnet/{tailnet}/acl` as JSON (`policy_file:read`): the policy
 * file without its comments. P0 only ever reads it.
 */
export const getPolicyJson = (
  call: TailnetCall
): Promise<Record<string, unknown>> =>
  get(
    call,
    tailnetPath(call, "/acl"),
    z.record(z.string(), z.unknown()),
    "the policy file",
    "policy_file:read"
  );
