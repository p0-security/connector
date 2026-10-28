/**
 * A Harbor double for the client's tests and the primitives' to come. It
 * copies what Harbor does (INT-255's "Harbor behaviours confirmed from
 * source", INT-265's research), or the tests prove nothing:
 *
 * - an ID token (`Authorization: Bearer`) is the Harbor user it was minted
 *   for, in OIDC mode only; any other caller is anonymous: `/systeminfo` and
 *   `GET /projects` still answer 200 (public projects only), the rest 401;
 * - a user who isn't a system administrator gets 403 on the user list, on
 *   member calls and on `PUT /users/{id}/sysadmin`, and sees public projects
 *   only;
 * - a project that doesn't exist answers a members call 403, and
 *   `HEAD /projects?project_name=` tells it apart (404 or 200);
 * - `PUT` and `DELETE` on a member id that isn't the project's answer 200 and
 *   change nothing;
 * - `POST` answers 201, 409 for a user with a direct role there, and 400 for
 *   a user that doesn't exist;
 * - the members list's `X-Total-Count` counts more rows than it returns;
 * - `?email=` matches a substring, ignoring case;
 * - a project segment that parses as an integer addresses a project by id,
 *   unless the call sends `X-Is-Resource-Name: true`;
 * - a body that isn't the call's shape answers 422;
 * - `GET /users/current` answers the token's user 200, with its CLI secret;
 * - a member row whose role id isn't one of Harbor's five is left out of the
 *   members list, unless `listsUnknownRoles` says otherwise;
 * - `PUT /users/{id}/sysadmin` answers anyone but a system administrator 403
 *   (from 2.13.6, 2.14.5 and 2.15.3), and 404 for a user that doesn't exist;
 * - the user list carries `sysadmin_flag`, and `admin_role_in_auth` as
 *   `false`, and filters exactly on `q=user_id=<id>`.
 */
import { vi } from "vitest";
import { z } from "zod";

import { HARBOR_HOST, ID_TOKEN } from "../../__tests__/fixtures.ts";
import { parseHarborVersion } from "../version.ts";

export const ORIGIN = `https://${HARBOR_HOST}`;

export type FakeUser = {
  user_id: number;
  username: string;
  email: string;
  sysadmin_flag?: boolean;
};
export type FakeMember = {
  id: number;
  entity_id: number;
  entity_type: "g" | "u";
  role_id: number;
};
export type FakeProject = {
  project_id: number;
  name: string;
  public: boolean;
  members: FakeMember[];
};

/** A member row: a user's (`"u"`) or a group's (`"g"`) role on a project. */
export const memberRow = (
  id: number,
  entity_id: number,
  role_id = 3,
  entity_type: "g" | "u" = "u"
): FakeMember => ({ id, entity_id, entity_type, role_id });

/** A project, private unless `isPublic`, with its member rows. */
export const fakeProject = (
  project_id: number,
  name: string,
  members: FakeMember[] = [],
  isPublic = false
): FakeProject => ({ project_id, name, public: isPublic, members });

export type FakeHarborState = {
  users: FakeUser[];
  projects: FakeProject[];
  /**
   * Projects whose members calls answer 404: deleted between Harbor's two
   * lookups of the project.
   */
  vanishing?: Set<string>;
  /**
   * Whether the members list shows a row whose role id isn't one of Harbor's
   * five. Harbor's list inner-joins the role table, so it is believed to
   * leave such a row out (INT-265's research, from source, not checked
   * live): that is the default. `true` is a Harbor that lists one.
   */
  listsUnknownRoles?: boolean;
  /** `harbor_version`. Public below 2.13, as Harbor's is. */
  version?: string;
  /** `auth_mode`. Harbor accepts an ID token only in `oidc_auth`. */
  authMode?: string;
  /** The ID token Harbor accepts. The fixtures' `ID_TOKEN` by default. */
  token?: string;
  /**
   * The id of the user in `users` the token signs in as. By default the
   * admin account, {@link ADMIN_ACCOUNT}, which the user list leaves out.
   */
  caller?: number;
};

/** The admin account the token signs in as by default: a system administrator. */
export const ADMIN_ACCOUNT: FakeUser = {
  user_id: 9000,
  username: "harbor-automation",
  email: "harbor-automation@example.com",
  sysadmin_flag: true,
};

/** What a user record holds in OIDC mode, which the connector must never read. */
export const CLI_SECRET = "SENTINEL-cli-secret-2b9d";

const json = (
  body: unknown,
  status = 200,
  headers: Record<string, string> = {}
) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

const error = (status: number, code: string, message: string) =>
  json({ errors: [{ code, message }] }, status);

const unauthorized = () => error(401, "UNAUTHORIZED", "unauthorized");
const forbidden = () => error(403, "FORBIDDEN", "forbidden");

const page = <T>(rows: T[], query: URLSearchParams) => {
  const number = Number(query.get("page") ?? 1);
  const size = Number(query.get("page_size") ?? 10);
  return rows.slice((number - 1) * size, number * size);
};

/** The JSON a call sent. */
export const sentJson = (init?: RequestInit): unknown => {
  if (typeof init?.body !== "string") throw new Error("no JSON body");
  return JSON.parse(init.body);
};

// The bodies Harbor's API takes (swagger's ProjectMember and RoleRequest).
const addMemberBody = z.object({
  role_id: z.number().int(),
  member_user: z.object({ user_id: z.number().int() }),
});
const updateMemberBody = z.object({ role_id: z.number().int() });

/** The call's body as `schema` says, or `undefined` when it isn't. */
const bodyOf = <T>(init: RequestInit, schema: z.ZodType<T>) => {
  try {
    const parsed = schema.safeParse(sentJson(init));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
};

const sysadminBody = z.object({ sysadmin_flag: z.boolean() });

/** A user as the user list shows them. */
const listed = ({ sysadmin_flag = false, ...user }: FakeUser) => ({
  ...user,
  sysadmin_flag,
  // Harbor's list never knows the identity provider's admin group.
  admin_role_in_auth: false,
  creation_time: "2026-10-01T00:00:00Z",
});

const unprocessable = () =>
  error(422, "UNPROCESSABLE_ENTITY", "validation failure");

export const newFakeHarbor = (state: FakeHarborState) => {
  let nextMemberId = 1000;

  const answer = async (
    input: string,
    init: RequestInit = {}
  ): Promise<Response> => {
    const url = new URL(input);
    const method = init.method ?? "GET";
    // The Harbor user the ID token signs in as, in OIDC mode, or
    // `undefined` for an anonymous caller.
    const bearer = new Headers(init.headers).get("authorization");
    const tokenUser =
      (state.authMode ?? "oidc_auth") === "oidc_auth" &&
      bearer === `Bearer ${state.token ?? ID_TOKEN}`
        ? state.caller === undefined
          ? ADMIN_ACCOUNT
          : state.users.find(({ user_id }) => user_id === state.caller)
        : undefined;
    const authed = tokenUser !== undefined;
    const admin = tokenUser?.sysadmin_flag === true;
    const path = url.pathname.replace(/^\/api\/v2\.0/, "");
    const query = url.searchParams;

    if (path === "/systeminfo" && method === "GET") {
      const version = state.version ?? "v2.14.0-44a74424";
      // Harbor tells anyone its version up to 2.12.4.
      const parsed = parseHarborVersion(version);
      const versionIsPublic =
        parsed !== undefined &&
        (parsed.major < 2 || (parsed.major === 2 && parsed.minor <= 12));
      return json({
        auth_mode: state.authMode ?? "oidc_auth",
        ...(authed || versionIsPublic ? { harbor_version: version } : {}),
        ...(authed ? { current_time: "2026-10-12T22:00:00Z" } : {}),
      });
    }

    if (path === "/users/current" && method === "GET") {
      if (!tokenUser) return unauthorized();
      return json({
        ...listed(tokenUser),
        oidc_user_meta: { secret: CLI_SECRET },
      });
    }

    const sysadmin = /^\/users\/(\d+)\/sysadmin$/.exec(path);
    if (sysadmin && method === "PUT") {
      if (!authed) return unauthorized();
      // GHSA-w5fq-xrhj-j7g2's fix: a system administrator only.
      if (!admin) return forbidden();
      const body = bodyOf(init, sysadminBody);
      if (!body) return unprocessable();
      const target = state.users.find(
        ({ user_id }) => user_id === Number(sysadmin[1])
      );
      if (!target) return error(404, "NOT_FOUND", "user not found");
      target.sysadmin_flag = body.sysadmin_flag;
      return new Response(null, { status: 200 });
    }

    if (path === "/users" && method === "GET") {
      if (!authed) return unauthorized();
      if (!admin) return forbidden();
      const email = query.get("email")?.toLowerCase();
      const byId = /^user_id=(\d+)$/.exec(query.get("q") ?? "");
      const rows = state.users
        .filter((user) => !email || user.email.toLowerCase().includes(email))
        .filter((user) => !byId || user.user_id === Number(byId[1]))
        .map(listed);
      return json(page(rows, query), 200, {
        "x-total-count": String(rows.length),
      });
    }

    if (path === "/projects" && method === "HEAD") {
      if (!authed) return new Response(null, { status: 401 });
      const name = query.get("project_name");
      return new Response(null, {
        status: state.projects.some((project) => project.name === name)
          ? 200
          : 404,
      });
    }

    if (path === "/projects" && method === "GET") {
      const rows = state.projects
        .filter((project) => project.public || admin)
        .map(({ project_id, name }) => ({ project_id, name }));
      return json(page(rows, query), 200, {
        "x-total-count": String(rows.length),
      });
    }

    const members = /^\/projects\/([^/]+)\/members(?:\/([^/]+))?$/.exec(path);
    if (members) {
      if (!authed) return unauthorized();
      const segment = decodeURIComponent(members[1] ?? "");
      // Harbor reads a segment Go's ParseInt takes as an id, unless told
      // it's a name.
      const project =
        new Headers(init.headers).get("x-is-resource-name") !== "true" &&
        /^[+-]?\d+$/.test(segment)
          ? state.projects.find((p) => p.project_id === Number(segment))
          : state.projects.find((p) => p.name === segment);
      const name = project?.name ?? segment;
      if (state.vanishing?.has(name)) {
        return error(404, "NOT_FOUND", "project not found");
      }
      const mid = members[2] === undefined ? undefined : Number(members[2]);
      // The permission is checked on the project, and Harbor finds none on a
      // project that doesn't exist.
      if (!project || !admin) return forbidden();

      if (method === "GET" && mid === undefined) {
        // Harbor counts every member row, groups included, and more besides.
        const listed = state.listsUnknownRoles
          ? project.members
          : project.members.filter(
              ({ role_id }) => role_id >= 1 && role_id <= 5
            );
        return json(page(listed, query), 200, {
          "x-total-count": String(project.members.length + 7),
        });
      }
      if (method === "POST" && mid === undefined) {
        const body = bodyOf(init, addMemberBody);
        if (!body) return unprocessable();
        const userId = body.member_user.user_id;
        if (!state.users.some((user) => user.user_id === userId)) {
          return error(
            400,
            "BAD_REQUEST",
            `Failed to get user ${userId}: not found`
          );
        }
        if (
          project.members.some(
            (member) =>
              member.entity_type === "u" && member.entity_id === userId
          )
        ) {
          return error(409, "CONFLICT", "The member already exists");
        }
        const id = nextMemberId++;
        project.members.push({
          id,
          entity_id: userId,
          entity_type: "u",
          role_id: body.role_id,
        });
        return new Response(null, {
          status: 201,
          headers: { location: `/api/v2.0/projects/${name}/members/${id}` },
        });
      }
      if (method === "PUT" && mid !== undefined) {
        const body = bodyOf(init, updateMemberBody);
        if (!body) return unprocessable();
        // Harbor updates where the id and the project match, and doesn't
        // look at how many rows that was.
        for (const member of project.members) {
          if (member.id === mid) member.role_id = body.role_id;
        }
        return new Response(null, { status: 200 });
      }
      if (method === "DELETE" && mid !== undefined) {
        project.members = project.members.filter((member) => member.id !== mid);
        return new Response(null, { status: 200 });
      }
    }

    return error(404, "NOT_FOUND", "not found");
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
  };
};
