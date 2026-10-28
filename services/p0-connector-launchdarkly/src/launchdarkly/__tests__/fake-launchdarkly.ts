/**
 * A LaunchDarkly double for the client's tests, the lookups' and the
 * accesses'. Its answers follow the shapes in LaunchDarkly's OpenAPI spec
 * (read 2026-10-17), or the tests prove nothing:
 *
 * - each instance answers on its own host only;
 * - `Authorization` is the access token itself, with no `Bearer`, and any
 *   other value answers 401 `unauthorized`;
 * - a call without `LD-API-Version: 20240415` answers 400, standing in for
 *   a version the fake doesn't speak;
 * - `GET /caller-identity` answers `CallerIdentityRep`;
 * - `GET /members` pages with `limit` and `offset`, 20 rows by default, and
 *   answers its collection with `totalCount`;
 * - `GET /members` takes an `email:` filter, a `|`-separated list of emails,
 *   each matched exactly, case included (REST check 1 assumes exact, and
 *   whether LaunchDarkly ignores case is open);
 * - `GET /members/{id}` answers `Member`;
 * - an error's body is `{ code, message, id }`;
 * - the one write the connector makes, `PATCH /members/{id}` (a bare JSON
 *   Patch on `/role`, with a `test`, applied all or nothing), answers as
 *   the spec has it, and changes the state;
 * - a failed JSON Patch `test` answers 409, or `testFailureStatus` (REST
 *   check 4 says which);
 * - any other route, or method, answers 404 `not_found`.
 */
import { vi } from "vitest";
import { z } from "zod";

import { ACCOUNT_ID, TOKEN, TOKEN_OWNER_ID } from "../../__tests__/fixtures.ts";
import { type Instance, LAUNCHDARKLY_HOSTS } from "../../account.ts";
import { parseJson } from "../api.ts";

/**
 * A member, as the spec's `Member` has it. `_verified` is `true` and
 * `_pendingInvite` `false` unless set.
 */
export type FakeMember = {
  _id: string;
  email: string;
  role: string;
  _verified?: boolean;
  _pendingInvite?: boolean;
  _pendingEmail?: string;
  /** The `_id`s of the custom roles assigned to the member directly. */
  customRoles?: string[];
  /** The member's `version`, 1 unless set, and raised by each change. */
  version?: number;
};

export type FakeLaunchDarklyState = {
  /** The instance that answers. Commercial by default. */
  instance?: Instance;
  /** The access token LaunchDarkly accepts. The fixtures' `TOKEN` by default. */
  token?: string;
  /** The account's id. The fixtures' `ACCOUNT_ID` by default. */
  accountId?: string;
  /**
   * What `GET /caller-identity` says of the token, besides `accountId`. A
   * service token by default.
   */
  caller?: Record<string, unknown>;
  members?: FakeMember[];
  /** What a failed JSON Patch `test` answers. 409 by default. */
  testFailureStatus?: 400 | 409;
};

/** A service token's caller identity, which names the member who made it. */
const SERVICE_CALLER = {
  authKind: "token",
  tokenKind: "api",
  tokenId: "64f0e1d2c3b4a5968778695a",
  tokenName: "p0-connector",
  serviceToken: true,
  memberId: "5e4d3c2b1a09f8e7d6c5b4a3",
  scopes: [],
};

/** A personal token's caller identity: it acts as its member. */
export const PERSONAL_CALLER = {
  authKind: "token",
  tokenKind: "api",
  tokenId: "64f0e1d2c3b4a5968778695b",
  tokenName: "p0-connector",
  serviceToken: false,
  memberId: TOKEN_OWNER_ID,
};

/** A member with the base role `reader`, unless `member` sets another. */
export const fakeMember = (
  member: Pick<FakeMember, "_id" | "email"> & Partial<FakeMember>
): FakeMember => ({ role: "reader", ...member });

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

/** LaunchDarkly's error body, with an id its support could look up. */
export const errorAnswer = (
  status: number,
  { code, message }: { code: string; message: string }
): Response =>
  json({ code, message, id: "30ce6058-87da-11e4-b116-123b93f75cba" }, status);

const notFound = () =>
  errorAnswer(404, {
    code: "not_found",
    message: "Invalid resource identifier",
  });

const links = (href: string) => ({ self: { href, type: "application/json" } });

// The write bodies the fake reads, as loosely as LaunchDarkly takes them:
// the fake answers anything else the way LaunchDarkly would.
const jsonPatchOperation = z.object({
  op: z.unknown(),
  path: z.unknown(),
  value: z.unknown(),
});

/** A request's JSON body, which the connector always sends as a string. */
const bodyOf = (init: RequestInit | undefined): unknown =>
  typeof init?.body === "string" ? JSON.parse(init.body) : undefined;

const page = <T>(items: T[], query: URLSearchParams, route: string) => {
  const limit = Number(query.get("limit") ?? 20);
  const offset = Number(query.get("offset") ?? 0);
  return {
    items: items.slice(offset, offset + limit),
    totalCount: items.length,
    _links: links(`${route}?limit=${limit}&offset=${offset}`),
  };
};

/** The path's one value after `prefix`, decoded, when it is that route. */
const valueAfter = (route: string, prefix: string) => {
  if (!route.startsWith(prefix)) return undefined;
  const value = route.slice(prefix.length);
  return value === "" || value.includes("/")
    ? undefined
    : decodeURIComponent(value);
};

export const newFakeLaunchDarkly = (state: FakeLaunchDarklyState = {}) => {
  const host = LAUNCHDARKLY_HOSTS[state.instance ?? "commercial"];

  const memberRep = (fake: FakeMember) => {
    const {
      customRoles = [],
      _verified = true,
      _pendingInvite = false,
      ...member
    } = fake;
    return {
      ...member,
      _links: links(`/api/v2/members/${member._id}`),
      _verified,
      _pendingInvite,
      customRoles,
      version: member.version ?? 1,
      mfa: "disabled",
      _lastSeen: 1608260796147,
      creationDate: 1628001602644,
      teams: [],
    };
  };

  const findMember = (id: string) =>
    (state.members ?? []).find(({ _id }) => _id === id);

  const changed = (member: FakeMember) => {
    member.version = (member.version ?? 1) + 1;
  };

  const badRequest = (message: string) =>
    errorAnswer(400, { code: "invalid_request", message });

  /** One JSON Patch operation on `role`, or the answer that refuses it. */
  const applyOperation = (
    role: string,
    { op, path, value }: z.infer<typeof jsonPatchOperation>
  ): Response | string => {
    if (op === "test" && path === "/role") {
      if (role === value) return role;
      return errorAnswer(state.testFailureStatus ?? 409, {
        code: "conflict",
        message: "The test operation failed",
      });
    }
    if (path === "/role" && (op === "replace" || op === "add")) {
      return String(value);
    }
    return badRequest(
      "You can update only an account member's role or custom role"
    );
  };

  /** `PATCH /members/{id}`: a JSON Patch, applied all or nothing. */
  const patchMember = (member: FakeMember, body: unknown): Response => {
    const parsed = z.array(jsonPatchOperation).safeParse(body);
    if (!parsed.success) return badRequest("Expected a JSON Patch");
    const patched = parsed.data.reduce<Response | string>(
      (sofar, operation) =>
        sofar instanceof Response ? sofar : applyOperation(sofar, operation),
      member.role
    );
    if (patched instanceof Response) return patched;
    member.role = patched;
    changed(member);
    return json(memberRep(member));
  };

  const write = (call: {
    method: string;
    rawBody: unknown;
    route: string;
  }): Response => {
    const { method, rawBody, route } = call;
    const body = parseJson(String(rawBody));
    if (body === undefined) return badRequest("The body isn't JSON");
    const memberId = valueAfter(route, "/api/v2/members/");
    if (method === "PATCH" && memberId !== undefined) {
      const member = findMember(memberId);
      return member === undefined ? notFound() : patchMember(member, body);
    }
    return notFound();
  };

  const answer = async (
    input: string,
    init: RequestInit = {}
  ): Promise<Response> => {
    const url = new URL(input);
    if (url.origin !== `https://${host}`) {
      throw new Error(`the fake answers https://${host} only`);
    }
    const method = init.method ?? "GET";
    const headers = new Headers(init.headers);
    if (headers.get("ld-api-version") !== "20240415") {
      return errorAnswer(400, {
        code: "invalid_request",
        message: "Unsupported API version",
      });
    }
    if (headers.get("authorization") !== (state.token ?? TOKEN)) {
      return errorAnswer(401, {
        code: "unauthorized",
        message: "Invalid access token",
      });
    }
    const query = url.searchParams;
    const route = url.pathname;
    if (method !== "GET") return write({ method, rawBody: init.body, route });

    if (route === "/api/v2/caller-identity") {
      return json({
        accountId: state.accountId ?? ACCOUNT_ID,
        ...(state.caller ?? SERVICE_CALLER),
      });
    }

    if (route === "/api/v2/members") {
      const filter = query.get("filter");
      const emails = filter?.startsWith("email:")
        ? filter.slice("email:".length).split("|")
        : undefined;
      const members = (state.members ?? []).filter(
        ({ email }) => emails === undefined || emails.includes(email)
      );
      return json(page(members.map(memberRep), query, route));
    }
    const memberId = valueAfter(route, "/api/v2/members/");
    if (memberId !== undefined) {
      const member = findMember(memberId);
      return member === undefined ? notFound() : json(memberRep(member));
    }

    return notFound();
  };

  const fetchMock = vi.fn(answer);
  vi.stubGlobal("fetch", fetchMock);
  return {
    state,
    fetch: fetchMock,
    /** Each call's method and URL. */
    calls: () =>
      fetchMock.mock.calls.map(
        ([url, init]) => `${init?.method ?? "GET"} ${url}`
      ),
    /** Each call that isn't a `GET`: its method and URL, content type and body. */
    writes: () =>
      fetchMock.mock.calls
        .filter(([, init]) => (init?.method ?? "GET") !== "GET")
        .map(([url, init]) => ({
          call: `${init?.method ?? "GET"} ${url}`,
          contentType: new Headers(init?.headers).get("content-type"),
          body: bodyOf(init),
        })),
    /**
     * Answers a call with `override`'s response when it gives one, and as
     * the fake does otherwise: for answers a real LaunchDarkly gives that
     * the fake can't be set up for. `next` is the fake's own answer.
     */
    intercept: (
      override: (
        call: { method: string; url: string; body: unknown },
        next: () => Promise<Response>
      ) => Promise<Response | undefined> | Response | undefined
    ) => {
      fetchMock.mockImplementation(async (url, init = {}) => {
        const method = init.method ?? "GET";
        const body = bodyOf(init);
        return (
          (await override({ method, url, body }, () => answer(url, init))) ??
          (await answer(url, init))
        );
      });
    },
  };
};
