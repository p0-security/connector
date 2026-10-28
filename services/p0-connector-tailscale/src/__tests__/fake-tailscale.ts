import { type ParseError, parse as parseJsonc } from "jsonc-parser";
import { vi } from "vitest";

import { identityTokenFor } from "./fixtures.ts";

/**
 * One tailnet behind `fetch`: Tailscale's token endpoints and the API
 * endpoints the connector calls, answering in the shapes Tailscale's OpenAPI
 * spec gives, over state a test can read and change. Every token carries
 * scopes, and an endpoint answers a token without the one it needs with
 * 404 "not found", as Tailscale does.
 */

/** How long Tailscale's access tokens last: an hour, fixed. */
export const TOKEN_LIFETIME_S = 60 * 60;

export const ORIGIN = "https://api.tailscale.com";

/** A request the connector sent, as Tailscale would see it. */
export type TailscaleCall = {
  method: string;
  url: string;
  host: string;
  /** The path as sent, still percent-encoded. */
  path: string;
  query: Record<string, string>;
  /** Lowercased names, as `Headers` gives them. */
  headers: Record<string, string>;
  rawBody: string | undefined;
  /** A form body, as fields. */
  form: Record<string, string> | undefined;
  redirect: string | undefined;
};

export type TailscaleReply =
  | { status: number; body?: unknown; headers?: Record<string, string> }
  | { throws: unknown };

/** Tailscale failing a call, with its usual error body. */
export const failing = (
  status: number,
  message = "error",
  headers?: Record<string, string>
): TailscaleReply => ({ status, body: { message }, headers });

export type FakeUser = { id: string; loginName: string; role?: string };

export type FakeDevice = {
  nodeId: string;
  id?: string;
  name?: string;
  hostname?: string;
  user?: string;
  tags?: string[];
  /** True for a device another tailnet shares in. */
  isExternal?: boolean;
  advertisedRoutes?: string[];
  enabledRoutes?: string[];
  /** The device's attributes, its own and Tailscale's. */
  attributes?: Record<string, boolean | number | string>;
  expiries?: Record<string, string>;
};

export type FakeService = { name: string };

/** An OAuth client: its secret and the scopes it was created with. */
export type FakeClient = { secret: string; scopes: string[] };

/** A federated identity: the scopes it was created with. */
export type FakeIdentity = { scopes: string[] };

type IssuedToken = { scopes: string[]; clientId: string };

/**
 * Whether `held` grants `needed`: a write scope implies its `:read`, `all`
 * every scope, and `all:read` every `:read` one.
 */
export const grants = (held: readonly string[], needed: string): boolean =>
  held.includes(needed) ||
  held.includes("all") ||
  (needed.endsWith(":read") &&
    (held.includes("all:read") || held.includes(needed.slice(0, -5))));

export const newFakeTailscale = ({
  tailnet,
  clients = {},
  identities = {},
  refuseUnheldScopes = true,
}: {
  tailnet: string;
  clients?: Record<string, FakeClient>;
  identities?: Record<string, FakeIdentity>;
  /**
   * Whether the token endpoint refuses a scope the client doesn't hold, as
   * Tailscale does, or issues a token without it.
   */
  refuseUnheldScopes?: boolean;
}) => {
  const state = {
    users: [] as FakeUser[],
    devices: [] as FakeDevice[],
    services: [] as FakeService[],
    /** The policy file as stored, byte for byte. */
    policy: "{}",
  };
  const calls: TailscaleCall[] = [];
  const issued = new Map<string, IssuedToken>();
  const tokens: string[] = [];
  let interceptor:
    | ((call: TailscaleCall) => TailscaleReply | undefined)
    | undefined;

  const issue = (clientId: string, scopes: string[]): TailscaleReply => {
    const token = `tskey-api-${tokens.length + 1}SENTINELtok${clientId.length}`;
    tokens.push(token);
    issued.set(token, { scopes, clientId });
    return {
      status: 200,
      body: {
        access_token: token,
        token_type: "Bearer",
        expires_in: TOKEN_LIFETIME_S,
        scope: scopes.join(" "),
      },
    };
  };

  const exchange = ({ form }: TailscaleCall): TailscaleReply => {
    const client = clients[form?.client_id ?? ""];
    if (
      form?.grant_type !== "client_credentials" ||
      !client ||
      client.secret !== form.client_secret
    ) {
      return {
        status: 401,
        body: { error: "invalid_client", error_description: "invalid client" },
      };
    }
    const asked = (form.scope ?? "").split(" ").filter(Boolean);
    const scopes = asked.length > 0 ? asked : client.scopes;
    const held = scopes.filter((scope) => grants(client.scopes, scope));
    if (held.length < scopes.length && refuseUnheldScopes) {
      // Tailscale's answer, naming every scope asked for, sorted.
      return failing(
        403,
        `OAuth client cannot grant scopes "${[...scopes].sort().join(" ")}"`
      );
    }
    return issue(form.client_id ?? "", held);
  };

  const federate = ({ form }: TailscaleCall): TailscaleReply => {
    const clientId = form?.client_id ?? "";
    const identity = identities[clientId];
    if (
      !identity ||
      form?.jwt !== identityTokenFor(`api.tailscale.com/${clientId}`)
    ) {
      return { status: 401, body: { message: "invalid token" } };
    }
    return issue(clientId, identity.scopes);
  };

  /** The file parsed as HuJSON, or `undefined` when it doesn't parse. */
  const parsePolicy = (text: string): Record<string, unknown> | undefined => {
    const errors: ParseError[] = [];
    const value = parseJsonc(text, errors, { allowTrailingComma: true });
    return errors.length === 0 && typeof value === "object" && value !== null
      ? (value as Record<string, unknown>)
      : undefined;
  };
  const policyJson = (): unknown => parsePolicy(state.policy);

  /** Tailscale's answer to a read of a device that isn't on the tailnet. */
  const noDevice = () =>
    failing(404, "no manageable device matching this ID found");

  const findDevice = (id: string) =>
    state.devices.find((device) => device.nodeId === id || device.id === id);

  const deviceJson = (device: FakeDevice, all: boolean) => {
    const {
      attributes: _a,
      expiries: _e,
      advertisedRoutes,
      enabledRoutes,
      ...rest
    } = device;
    return all ? { ...rest, advertisedRoutes, enabledRoutes } : rest;
  };

  /** What each endpoint needs, and how it answers. */
  const route = (
    call: TailscaleCall,
    segments: string[]
  ): { scope: string; answer: () => TailscaleReply } | undefined => {
    const { method, query } = call;
    const [kind, id, sub, key] = segments;
    if (kind === "tailnet") {
      if (id !== tailnet && id !== "-") {
        return { scope: "", answer: () => failing(404, "tailnet not found") };
      }
      if (method === "GET" && sub === "users") {
        return {
          scope: "users:read",
          answer: () => ({ status: 200, body: { users: state.users } }),
        };
      }
      if (method === "GET" && sub === "devices") {
        return {
          scope: "devices:core:read",
          answer: () => {
            const { fields, ...filters } = query;
            const devices = state.devices.filter((device) =>
              Object.entries(filters).every(
                ([field, value]) =>
                  (device as Record<string, unknown>)[field] === value
              )
            );
            return {
              status: 200,
              body: {
                devices: devices.map((device) =>
                  deviceJson(device, fields === "all")
                ),
              },
            };
          },
        };
      }
      if (method === "GET" && sub === "services") {
        return {
          scope: "services:read",
          answer: () => ({
            status: 200,
            body: { vipServices: state.services },
          }),
        };
      }
      if (method === "PATCH" && sub === "device-attributes") {
        return {
          scope: "devices:posture_attributes",
          answer: () => {
            const body = JSON.parse(call.rawBody ?? "{}") as {
              nodes?: Record<
                string,
                Record<
                  string,
                  { value: boolean | number | string; expiry?: string } | null
                >
              >;
            };
            const nodes = Object.entries(body.nodes ?? {});
            // Tailscale's answer for a device that isn't on the tailnet.
            if (nodes.some(([id]) => !findDevice(id))) {
              return failing(
                403,
                "feature not available on current billing plan"
              );
            }
            for (const [id, patch] of nodes) {
              const device = findDevice(id);
              if (!device) continue;
              const attributes = { ...device.attributes };
              const expiries = { ...device.expiries };
              for (const [name, change] of Object.entries(patch)) {
                if (!name.startsWith("custom:"))
                  return failing(400, "not a custom key");
                if (change === null) {
                  delete attributes[name];
                  delete expiries[name];
                } else {
                  attributes[name] = change.value;
                  // Tailscale keeps the expiry to the second (spec check A49).
                  if (change.expiry !== undefined)
                    expiries[name] = change.expiry.replace(/\.\d+Z$/, "Z");
                  else delete expiries[name];
                }
              }
              device.attributes = attributes;
              device.expiries = expiries;
            }
            return { status: 200, body: null };
          },
        };
      }
      if (method === "GET" && sub === "acl") {
        return {
          scope: "policy_file:read",
          answer: () => ({ status: 200, body: policyJson() }),
        };
      }
      return undefined;
    }
    if (kind === "device" && id !== undefined) {
      const device = findDevice(id);
      // A shared-in device's routes and attributes are its own tailnet's,
      // so their reads are refused here, as Tailscale may.
      const own = device?.isExternal === true ? undefined : device;
      if (method === "GET" && sub === undefined) {
        return {
          scope: "devices:core:read",
          answer: () =>
            device
              ? {
                  status: 200,
                  body: deviceJson(device, query.fields === "all"),
                }
              : noDevice(),
        };
      }
      if (method === "GET" && sub === "routes") {
        return {
          scope: "devices:routes:read",
          answer: () =>
            own
              ? {
                  status: 200,
                  body: {
                    advertisedRoutes: own.advertisedRoutes ?? [],
                    enabledRoutes: own.enabledRoutes ?? [],
                  },
                }
              : noDevice(),
        };
      }
      if (method === "GET" && sub === "attributes" && key === undefined) {
        return {
          scope: "devices:posture_attributes:read",
          answer: () =>
            own
              ? {
                  status: 200,
                  body: {
                    attributes: own.attributes ?? {},
                    expiries: own.expiries ?? {},
                  },
                }
              : noDevice(),
        };
      }
      if (sub === "attributes" && key !== undefined) {
        if (method === "POST") {
          return {
            scope: "devices:posture_attributes",
            answer: () => {
              if (!device) return failing(404, "not found");
              const body = JSON.parse(call.rawBody ?? "{}") as {
                value: boolean | number | string;
                expiry?: string;
              };
              device.attributes = { ...device.attributes, [key]: body.value };
              if (body.expiry !== undefined) {
                device.expiries = { ...device.expiries, [key]: body.expiry };
              }
              return { status: 200, body: null };
            },
          };
        }
        if (method === "DELETE") {
          return {
            scope: "devices:posture_attributes",
            answer: () => {
              if (!device) return failing(404, "not found");
              const { [key]: _gone, ...attributes } = device.attributes ?? {};
              const { [key]: _expiry, ...expiries } = device.expiries ?? {};
              device.attributes = attributes;
              device.expiries = expiries;
              return { status: 200, body: null };
            },
          };
        }
      }
    }
    return undefined;
  };

  const answer = (call: TailscaleCall): TailscaleReply => {
    if (call.host !== "api.tailscale.com") {
      return { throws: new TypeError("fetch failed") };
    }
    if (call.method === "POST" && call.path === "/api/v2/oauth/token") {
      return exchange(call);
    }
    if (
      call.method === "POST" &&
      call.path === "/api/v2/oauth/token-exchange"
    ) {
      return federate(call);
    }
    const [api, version, ...segments] = call.path
      .split("/")
      .filter(Boolean)
      .map(decodeURIComponent);
    if (api !== "api" || version !== "v2") return failing(404, "not found");
    const token = issued.get(
      call.headers.authorization?.replace(/^Bearer /, "") ?? ""
    );
    if (!token) return failing(401, "invalid token");
    const found = route(call, segments);
    if (!found) return failing(404, "not found");
    // Tailscale answers a missing scope as it does a missing object.
    if (found.scope !== "" && !grants(token.scopes, found.scope)) {
      return failing(404, "not found");
    }
    return found.answer();
  };

  const fetch = vi.fn<typeof globalThis.fetch>(async (resource, init) => {
    const url = new URL(
      resource instanceof Request ? resource.url : resource.toString()
    );
    const rawBody = typeof init?.body === "string" ? init.body : undefined;
    const headers = Object.fromEntries(new Headers(init?.headers));
    const call: TailscaleCall = {
      method: init?.method ?? "GET",
      url: url.toString(),
      host: url.host,
      path: url.pathname,
      query: Object.fromEntries(url.searchParams),
      headers,
      rawBody,
      form:
        headers["content-type"] === "application/x-www-form-urlencoded" &&
        rawBody !== undefined
          ? Object.fromEntries(new URLSearchParams(rawBody))
          : undefined,
      redirect: init?.redirect,
    };
    calls.push(call);
    const reply = interceptor?.(call) ?? answer(call);
    if ("throws" in reply) throw reply.throws;
    const { status, body, headers: replyHeaders } = reply;
    return new Response(
      body === undefined
        ? null
        : typeof body === "string"
          ? body
          : JSON.stringify(body),
      { status, headers: replyHeaders }
    );
  });

  const isExchange = ({ path }: TailscaleCall) =>
    path.startsWith("/api/v2/oauth/");

  return {
    /** Stub the global `fetch` with this, and no real network call is made. */
    fetch,
    /** The tailnet's users, devices, services and policy file, to read or to change. */
    state,
    /** Every request sent, in order. */
    calls,
    /** Every access token issued, in order. */
    tokens,
    /** The scopes each issued token carries. */
    scopesOf: (token: string) => issued.get(token)?.scopes,
    /** Tailscale stops accepting every access token it issued. */
    revokeTokens: () => issued.clear(),
    /** Answers a call some other way, whenever `reply` returns an answer. */
    intercept: (reply: (call: TailscaleCall) => TailscaleReply | undefined) => {
      interceptor = reply;
    },
    /** The token exchanges sent. */
    exchanges: () => calls.filter(isExchange),
    /** Every other request sent: the ones that carry an access token. */
    apiCalls: () => calls.filter((call) => !isExchange(call)),
    /** What was asked to change: every request but a `GET` and the token exchanges. */
    writes: () =>
      calls
        .filter((call) => call.method !== "GET" && !isExchange(call))
        .map(({ method, path, rawBody }) => ({ method, path, rawBody })),
    /** The scopes of the token each API call carried, in order. */
    scopesSent: () =>
      calls
        .filter((call) => !isExchange(call))
        .map(
          ({ headers }) =>
            issued.get(headers.authorization?.replace(/^Bearer /, "") ?? "")
              ?.scopes
        ),
  };
};

export type FakeTailscale = ReturnType<typeof newFakeTailscale>;

/** Matches a call by its method and its path, for {@link FakeTailscale.intercept}. */
export const isCall =
  (method: string, path: RegExp | string) =>
  (call: TailscaleCall): boolean =>
    call.method === method &&
    (typeof path === "string" ? call.path === path : path.test(call.path));
