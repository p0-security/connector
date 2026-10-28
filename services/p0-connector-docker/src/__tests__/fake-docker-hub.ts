import { vi } from "vitest";
import { z } from "zod";

/**
 * Docker Hub, for one organization, behind `fetch`: the endpoints the
 * connector calls, answering as INT-213 saw them answer, over members and
 * invites a test can read and change.
 */

const CORE_ROLES = ["member", "editor", "owner"];

/** How long Docker Hub's JWTs last. */
export const JWT_LIFETIME_MS = 15 * 60 * 1000;

export type HubMember = {
  username: string;
  uuid: string;
  email: string;
  /** A core role, lower-case, or a custom role's name. */
  role: string;
};

export type HubInvite = { id: string; invitee: string; role: string };

/** A request the connector sent, as Docker Hub would see it. */
export type HubCall = {
  method: string;
  url: string;
  /** The path as sent, still percent-encoded. */
  path: string;
  query: Record<string, string>;
  /** Lowercased names, as `Headers` gives them. */
  headers: Record<string, string>;
  /** The body as sent, and parsed. */
  rawBody: string | undefined;
  body: unknown;
  redirect: string | undefined;
};

export type HubReply =
  | { status: number; body?: unknown; headers?: Record<string, string> }
  | { throws: unknown };

/** Docker Hub failing a call, with its usual error body when there's a message. */
export const failing = (
  status: number,
  message?: string,
  headers?: Record<string, string>
): HubReply => ({
  status,
  body: message === undefined ? undefined : { message, errinfo: null },
  headers,
});

const UNAUTHORIZED = failing(401, "unauthorized");
const NOT_FOUND = failing(404, "not found");
const BAD_REQUEST = failing(400, "bad request");

const exchangeBody = z.object({ identifier: z.string(), secret: z.string() });
const roleBody = z.object({ role: z.string() });
const bulkInviteBody = z.object({
  org: z.string(),
  role: z.string(),
  invitees: z.array(z.string()),
  dry_run: z.boolean().optional(),
});

const capitalise = (role: string) =>
  `${role.charAt(0).toUpperCase()}${role.slice(1)}`;

const base64url = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

/** A JWT shaped like Docker Hub's, whose payload says when it expires. */
export const jwtExpiringAt = (expiresAt: number, n = 1): string =>
  [
    base64url({ alg: "RS256", typ: "JWT" }),
    base64url({ exp: Math.floor(expiresAt / 1000), jti: `jwt-${n}` }),
    `c2lnbmF0dXJl${n}`,
  ].join(".");

// A member as the member endpoints return one. `role` is capitalised and only
// ever a core role, so a custom role shows in `assigned_role` alone.
const memberJson = ({ username, uuid, email, role }: HubMember) => {
  const core = CORE_ROLES.includes(role);
  return {
    id: uuid.replaceAll("-", ""),
    uuid,
    username,
    full_name: capitalise(username),
    email,
    role: core ? capitalise(role) : "Member",
    groups: [],
    is_guest: false,
    type: "User",
    assigned_role: {
      id: `role-${role}`,
      name: role,
      label: capitalise(role),
      description: "",
      is_system: core,
    },
  };
};

type Options = {
  org: string;
  /** The organization access token Docker Hub exchanges. Any other is refused. */
  token: string;
  /** The JWTs it issues, numbered from 1. By default, ones that expire in 15 minutes. */
  jwt?: (n: number) => string;
  /** The most members on a page, whatever page size is asked for. */
  maxPageSize?: number;
};

export const newFakeDockerHub = ({
  org,
  token,
  jwt = (n) => jwtExpiringAt(Date.now() + JWT_LIFETIME_MS, n),
  maxPageSize = 100,
}: Options) => {
  const members: HubMember[] = [];
  const invites: HubInvite[] = [];
  const calls: HubCall[] = [];
  /** Every JWT issued, in order. */
  const jwts: string[] = [];
  /** The JWTs Docker Hub still accepts, and until when. */
  const live = new Map<string, number>();
  let interceptor: ((call: HubCall) => HubReply | undefined) | undefined;
  let invitesSent = 0;

  const sameEmail = (a: string, b: string) =>
    a.toLowerCase() === b.toLowerCase();

  const listMembers = ({ path, query }: HubCall): HubReply => {
    // Looser than Docker Hub's search, which matches a username, its prefix,
    // an exact email and an email's local part: this matches anywhere in
    // either, so whoever asks still has to pick out the exact match.
    const search = query.search?.toLowerCase();
    const found = members.filter(
      ({ username, email }) =>
        search === undefined ||
        username.toLowerCase().includes(search) ||
        email.toLowerCase().includes(search)
    );
    const page = Number(query.page ?? "1");
    const size = Math.min(Number(query.page_size ?? "25"), maxPageSize);
    const start = (page - 1) * size;
    const more = start + size < found.length;
    return {
      status: 200,
      body: {
        count: found.length,
        next: more
          ? `https://hub.docker.com${path}?page=${page + 1}&page_size=${size}`
          : null,
        previous: null,
        results: found.slice(start, start + size).map(memberJson),
      },
    };
  };

  const changeMember = (
    { method, body }: HubCall,
    username: string
  ): HubReply => {
    const index = members.findIndex(
      (member) => member.username.toLowerCase() === username.toLowerCase()
    );
    const member = members[index];
    if (!member) return NOT_FOUND;
    if (method === "DELETE") {
      members.splice(index, 1);
      return { status: 204 };
    }
    if (method === "PUT") {
      const parsed = roleBody.safeParse(body);
      if (!parsed.success) return BAD_REQUEST;
      member.role = parsed.data.role;
      return { status: 200, body: memberJson(member) };
    }
    return NOT_FOUND;
  };

  const bulkInvite = ({ body }: HubCall): HubReply => {
    const parsed = bulkInviteBody.safeParse(body);
    if (!parsed.success || parsed.data.org !== org) return BAD_REQUEST;
    const { role, invitees, dry_run: dryRun } = parsed.data;
    // What Docker Hub does with a second invite to the same address wasn't
    // tried. A conflict is the answer that hides the least here: a caller
    // that invites twice fails.
    if (
      !dryRun &&
      invitees.some((invitee) =>
        invites.some((invite) => sameEmail(invite.invitee, invitee))
      )
    ) {
      return failing(409, "conflict");
    }
    return {
      status: 202,
      body: {
        invitees: invitees.map((invitee) => {
          if (members.some(({ email }) => sameEmail(email, invitee))) {
            return { invitee, status: "existing_org_member" };
          }
          // A dry run validates, and nothing more.
          if (dryRun) return { invitee, status: "invited" };
          const invite = { id: `invite-${++invitesSent}`, invitee, role };
          invites.push(invite);
          return {
            invitee,
            status: "invited",
            invite: { ...invite, inviter_username: `${org}-oat`, org },
          };
        }),
      },
    };
  };

  const cancelInvite = (id: string): HubReply => {
    const index = invites.findIndex((invite) => invite.id === id);
    if (index < 0) return NOT_FOUND;
    invites.splice(index, 1);
    return { status: 204 };
  };

  const isLive = (bearer: string | undefined) => {
    const expiresAt = bearer === undefined ? undefined : live.get(bearer);
    return expiresAt !== undefined && Date.now() < expiresAt;
  };

  const answer = (call: HubCall): HubReply => {
    const { method, path, body, headers } = call;
    const [version, first, second, third, fourth, ...rest] = path
      .split("/")
      .filter(Boolean)
      .map(decodeURIComponent);
    if (version !== "v2" || rest.length > 0) return NOT_FOUND;

    if (
      method === "POST" &&
      first === "auth" &&
      second === "token" &&
      third === undefined
    ) {
      const parsed = exchangeBody.safeParse(body);
      if (
        !parsed.success ||
        parsed.data.identifier !== org ||
        parsed.data.secret !== token
      ) {
        return UNAUTHORIZED;
      }
      const issued = jwt(jwts.length + 1);
      jwts.push(issued);
      live.set(issued, Date.now() + JWT_LIFETIME_MS);
      return { status: 200, body: { access_token: issued } };
    }

    // Everything else takes a JWT Docker Hub issued and that hasn't expired.
    if (!isLive(headers.authorization?.replace(/^Bearer /, ""))) {
      return UNAUTHORIZED;
    }

    if (first === "orgs" && second === org) {
      if (third === "members" && fourth === undefined && method === "GET") {
        return listMembers(call);
      }
      if (third === "members" && fourth !== undefined) {
        return changeMember(call, fourth);
      }
      if (third === "invites" && fourth === undefined && method === "GET") {
        return {
          status: 200,
          body: {
            data: invites.map((invite) => ({
              ...invite,
              inviter_username: `${org}-oat`,
              org,
              team: "",
            })),
          },
        };
      }
    }
    if (first === "invites" && third === undefined) {
      if (second === "bulk" && method === "POST") return bulkInvite(call);
      if (second !== undefined && method === "DELETE") {
        return cancelInvite(second);
      }
    }
    return NOT_FOUND;
  };

  const fetch = vi.fn<typeof globalThis.fetch>(async (resource, init) => {
    const url = new URL(
      resource instanceof Request ? resource.url : resource.toString()
    );
    const rawBody = typeof init?.body === "string" ? init.body : undefined;
    const call: HubCall = {
      method: init?.method ?? "GET",
      url: url.toString(),
      path: url.pathname,
      query: Object.fromEntries(url.searchParams),
      headers: Object.fromEntries(new Headers(init?.headers)),
      rawBody,
      body: rawBody === undefined ? undefined : JSON.parse(rawBody),
      redirect: init?.redirect,
    };
    calls.push(call);
    const reply = interceptor?.(call) ?? answer(call);
    if ("throws" in reply) throw reply.throws;
    const { status, body, headers } = reply;
    return new Response(
      body === undefined
        ? null
        : typeof body === "string"
          ? body
          : JSON.stringify(body),
      { status, headers }
    );
  });

  const isExchange = ({ path }: HubCall) => path === "/v2/auth/token";

  return {
    /** Stub the global `fetch` with this, and no real network call is made. */
    fetch,
    /** The org's members and pending invites, to read or to change. */
    members,
    invites,
    /** Every request sent, in order. */
    calls,
    jwts,
    /** Docker Hub stops accepting every JWT it issued. */
    revokeJwts: () => live.clear(),
    /** Answers a call some other way, whenever `reply` returns an answer. */
    intercept: (reply: (call: HubCall) => HubReply | undefined) => {
      interceptor = reply;
    },
    /** The token exchanges sent. */
    exchanges: () => calls.filter(isExchange),
    /** Every other request sent: the ones that carry a JWT. */
    apiCalls: () => calls.filter((call) => !isExchange(call)),
    /** The JWT each of those carried, in order. */
    bearers: () =>
      calls
        .filter((call) => !isExchange(call))
        .map(({ headers }) => headers.authorization?.replace(/^Bearer /, "")),
    /** What was asked to change: every request but a `GET` and the token exchange. */
    writes: () =>
      calls
        .filter((call) => call.method !== "GET" && !isExchange(call))
        .map(({ method, path, body }) => ({ method, path, body })),
  };
};

export type FakeDockerHub = ReturnType<typeof newFakeDockerHub>;

/** Matches a call by its method and its path, for {@link FakeDockerHub.intercept}. */
export const isCall =
  (method: string, path: RegExp | string) =>
  (call: HubCall): boolean =>
    call.method === method &&
    (typeof path === "string" ? call.path === path : path.test(call.path));
