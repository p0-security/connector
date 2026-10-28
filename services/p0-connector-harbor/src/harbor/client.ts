import { ConnectorError, type Logger } from "@p0security/connector";
import { z } from "zod";

import { type Instance, hostOf } from "../accesses/project-role/definition.ts";
import { readAdminCredential } from "../secrets.ts";
import {
  type HarborApi,
  type HarborCall,
  HarborError,
  newHarborApi,
  segment,
} from "./api.ts";
import { mintIdToken } from "./oidc.ts";

/** Rows a page asks for: Harbor's most. */
export const PAGE_SIZE = 100;

/**
 * The most full pages a listing reads before it gives up: 100,000 rows. A
 * server that always answers a full page would otherwise be paged forever.
 */
// TODO(INT-447): a time budget per listing as well. At 10 seconds a page,
// 1,000 pages outlast any deployment's timeout.
export const MAX_PAGES = 1000;

// Harbor's ids are positive integers in JSON numbers.
const id = z.number().int().positive();

// Harbor's names and emails are at most 255 characters (its database's
// columns), so a longer one isn't Harbor's.
const text = z.string().min(1).max(255);

const systemInfo = z.object({
  auth_mode: text,
  harbor_version: text.nullish(),
});

const userRow = z.object({
  user_id: id,
  username: text,
  // A user can have no email, in LDAP mode say.
  email: z.string().max(255).nullish(),
});

// The user list's row with the user's admin state. `admin_role_in_auth` isn't
// a column of Harbor's user table (src/pkg/user/dao/user.go): Harbor sets it
// on the signed-in user only, from the OIDC or LDAP admin group, so the list
// answers it `false`. Both are required, so a row without them fails the
// read rather than reading as "not an admin".
const userAdminRow = userRow.extend({
  sysadmin_flag: z.boolean(),
  admin_role_in_auth: z.boolean(),
});

// What `GET /users/current` is read for. Its body holds more, the user's CLI
// secret among it in OIDC mode, which the parse drops.
const currentUserRow = z.object({
  user_id: id,
  sysadmin_flag: z.boolean(),
});

const projectRow = z.object({ project_id: id, name: text });

const memberRow = z.object({
  id,
  entity_id: id,
  // "u" for a user, "g" for a group. Kept as a string, so a kind a later
  // Harbor adds is read and left to the caller rather than failing the page.
  entity_type: z.string().max(255),
  role_id: z.number().int(),
});

/**
 * A Harbor user, as the user list shows it. `email` is Harbor's spelling of
 * the email that was looked up, which matched ignoring case.
 */
export type HarborUser = { userId: number; username: string; email: string };

/** A Harbor user and their admin state, as the user list shows them. */
export type HarborUserAdmin = {
  userId: number;
  /** Harbor's `sysadmin_flag`: the flag P0 sets and clears. */
  sysadminFlag: boolean;
  /**
   * Harbor's `admin_role_in_auth`: admin through the identity provider's
   * admin group. The user list always answers `false` (see `userAdminRow`).
   */
  adminRoleInAuth: boolean;
};

/** A Harbor project. */
export type HarborProject = { projectId: number; name: string };

/** A row of a project's members: a user's or a group's direct role. */
export type HarborMember = {
  /** The membership's own id, which `PUT` and `DELETE` take. */
  memberId: number;
  /** The user's or the group's id. */
  entityId: number;
  /** `"u"` for a user, `"g"` for a group. */
  entityType: string;
  roleId: number;
};

/** The calls the client makes. */
export const HARBOR_CALLS = {
  systemInfo: { method: "GET", route: "/api/v2.0/systeminfo" },
  listUsers: { method: "GET", route: "/api/v2.0/users" },
  currentUser: { method: "GET", route: "/api/v2.0/users/current" },
  // Only a system administrator may set the flag: from 2.13.6, 2.14.5 and
  // 2.15.3 Harbor answers anyone else 403, a robot account included
  // (GHSA-w5fq-xrhj-j7g2).
  setSysadmin: { method: "PUT", route: "/api/v2.0/users/{user_id}/sysadmin" },
  listProjects: { method: "GET", route: "/api/v2.0/projects" },
  headProject: { method: "HEAD", route: "/api/v2.0/projects" },
  listMembers: {
    method: "GET",
    route: "/api/v2.0/projects/{project_name}/members",
  },
  addMember: {
    method: "POST",
    route: "/api/v2.0/projects/{project_name}/members",
  },
  updateMember: {
    method: "PUT",
    route: "/api/v2.0/projects/{project_name}/members/{mid}",
  },
  removeMember: {
    method: "DELETE",
    route: "/api/v2.0/projects/{project_name}/members/{mid}",
  },
} as const satisfies Record<string, HarborCall>;

/**
 * Every row of a paged listing, page by page, as the caller reads them. It
 * stops on a page shorter than {@link PAGE_SIZE}, never on a total: the
 * members list's `X-Total-Count` counts rows the list doesn't return. A
 * caller that has what it needs can stop early.
 *
 * A page longer than {@link PAGE_SIZE}, or more than {@link MAX_PAGES} full
 * pages, isn't how Harbor answers, and fails the listing.
 */
export async function* paged<T>(
  api: Pick<HarborApi, "unexpected">,
  call: HarborCall,
  readPage: (page: number) => Promise<T[]>
): AsyncGenerator<T, void, undefined> {
  for (let page = 1; page <= MAX_PAGES; page++) {
    const rows = await readPage(page);
    if (rows.length > PAGE_SIZE) throw api.unexpected(call, "too_many_rows");
    yield* rows;
    if (rows.length < PAGE_SIZE) return;
  }
  throw api.unexpected(call, "endless");
}

const adminOf = ({
  user_id,
  sysadmin_flag,
  admin_role_in_auth,
}: z.infer<typeof userAdminRow>): HarborUserAdmin => ({
  userId: user_id,
  sysadminFlag: sysadmin_flag,
  adminRoleInAuth: admin_role_in_auth,
});

const collect = async <T>(rows: AsyncIterable<T>): Promise<T[]> => {
  const all: T[] = [];
  for await (const row of rows) all.push(row);
  return all;
};

const pageQuery = (page: number) => ({
  page: String(page),
  page_size: String(PAGE_SIZE),
});

/**
 * `text` with ASCII `A` to `Z` lowered, and nothing else changed.
 *
 * Emails are compared ignoring ASCII case only. `toLowerCase` folds Unicode
 * too: the Kelvin sign `K` (U+212A) lowers to `k`, and `İ` to `i` plus a
 * combining dot, so a Harbor user with a look-alike email would match the
 * principal. Folding only ASCII keeps "equal ignoring case" to the case
 * differences an IdP or a person actually introduces, and refuses the rest.
 */
export const foldAsciiCase = (text: string) =>
  text.replace(/[A-Z]/g, (letter) => letter.toLowerCase());

/**
 * An id the connector sends, checked before it goes. Harbor stores a role id
 * as it is sent, and a member id goes into the path. Callers pass ids Harbor
 * gave them or roles.ts's, so a bad one is a bug.
 */
const idOf = (what: string, value: number) => {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${value} isn't a Harbor ${what} id`);
  }
  return value;
};

/**
 * The Harbor calls the connector makes, as the Harbor admin user on one
 * instance. Every method fails with a {@link HarborError} for anything Harbor
 * answers, or doesn't; `callHarbor` turns that into the error P0 shows.
 *
 * The client absorbs Harbor's traps, so a caller can't fall into them:
 * - a rejected credential is an anonymous caller, which some routes still
 *   answer 200, so a listing those routes answer proves the credential first;
 * - a project that doesn't exist answers a members call 403, so a project's
 *   routes ask whether it exists, and fail with `project_gone` when it
 *   doesn't;
 * - the user list's `email` filter is a substring match, so the client keeps
 *   the exact matches.
 */
export const newHarborClient = (api: HarborApi) => {
  /**
   * Proves Harbor accepts the ID token. Harbor treats a token it doesn't
   * accept as an anonymous caller, which `/systeminfo` and `GET /projects`
   * still answer with a 200. The user list answers an anonymous caller 401,
   * and a user who isn't an administrator 403.
   */
  const proveCredential = async (): Promise<void> => {
    await api.read({
      call: HARBOR_CALLS.listUsers,
      path: "/users",
      query: { page: "1", page_size: "1" },
      answer: z.array(z.unknown()),
    });
  };

  /**
   * Whether a project named `project` exists. Any authenticated caller may
   * ask, and Harbor answers 200 or 404.
   */
  const projectExists = async (project: string): Promise<boolean> => {
    try {
      await api.send({
        call: HARBOR_CALLS.headProject,
        path: "/projects",
        query: { project_name: project },
      });
      return true;
    } catch (error) {
      if (
        error instanceof HarborError &&
        error.failure.kind === "status" &&
        error.failure.status === 404
      ) {
        return false;
      }
      throw error;
    }
  };

  /**
   * Runs a call on one of `project`'s routes. Harbor answers 403 for a
   * project that doesn't exist, as it does for a caller who may not touch
   * it, so a 403 asks {@link projectExists}. A 404 means the project went
   * between Harbor's two lookups of it (INT-265, item 4). Either way the
   * call fails with `project_gone`, never a missing permission or "not
   * Harbor".
   */
  const onProject = async <T>(
    project: string,
    call: HarborCall,
    run: () => Promise<T>
  ): Promise<T> => {
    try {
      return await run();
    } catch (error) {
      if (!(error instanceof HarborError) || error.failure.kind !== "status") {
        throw error;
      }
      const { status } = error.failure;
      if (
        status === 404 ||
        (status === 403 && !(await projectExists(project)))
      ) {
        throw new HarborError(call, { kind: "project_gone", project });
      }
      throw error;
    }
  };

  /**
   * Every user row whose email is `email`, ignoring ASCII case
   * ({@link foldAsciiCase}), as `row` parses it. Harbor's filter is a
   * substring match, so every page is read and only the exact matches are
   * kept: a caller can tell one match from several. An empty email would
   * match every user, and is refused.
   */
  const usersByEmail = async <T extends z.infer<typeof userRow>>(
    email: string,
    row: z.ZodType<T>
  ): Promise<(T & { email: string })[]> => {
    if (!email.trim()) {
      throw new ConnectorError({
        type: "validation_error",
        message: "The connector needs an email to look a Harbor user up.",
        payload: {},
      });
    }
    const wanted = foldAsciiCase(email);
    const users: (T & { email: string })[] = [];
    const rows = paged(api, HARBOR_CALLS.listUsers, (page) =>
      api.read({
        call: HARBOR_CALLS.listUsers,
        path: "/users",
        query: { email, ...pageQuery(page) },
        answer: z.array(row),
      })
    );
    for await (const user of rows) {
      const { email: found } = user;
      if (
        found !== null &&
        found !== undefined &&
        foldAsciiCase(found) === wanted
      ) {
        users.push({ ...user, email: found });
      }
    }
    return users;
  };

  /**
   * The project's members, users and groups, page by page as the caller
   * reads them. A caller looking for one member can stop on it.
   */
  const members = (
    project: string
  ): AsyncGenerator<HarborMember, void, undefined> => {
    const call = HARBOR_CALLS.listMembers;
    const path = `/projects/${segment(project)}/members`;
    return paged(api, call, async (page) => {
      const rows = await onProject(project, call, () =>
        api.read({
          call,
          path,
          query: pageQuery(page),
          answer: z.array(memberRow),
        })
      );
      return rows.map(({ id, entity_id, entity_type, role_id }) => ({
        memberId: id,
        entityId: entity_id,
        entityType: entity_type,
        roleId: role_id,
      }));
    });
  };

  return {
    /**
     * Harbor's auth mode, and its version when Harbor tells it. Harbor
     * answers anyone, so this proves the instance answers as Harbor does,
     * not that it accepts the credential. The version is public up to 2.12.4
     * and for authenticated callers only from 2.13.0.
     */
    systemInfo: async (): Promise<{
      authMode: string;
      harborVersion?: string;
    }> => {
      const data = await api.read({
        call: HARBOR_CALLS.systemInfo,
        path: "/systeminfo",
        answer: systemInfo,
      });
      return {
        authMode: data.auth_mode,
        ...(data.harbor_version ? { harborVersion: data.harbor_version } : {}),
      };
    },

    proveCredential,

    /** Every user whose email is `email`, ignoring ASCII case (`usersByEmail`). */
    findUsersByEmail: async (email: string): Promise<HarborUser[]> => {
      const rows = await usersByEmail(email, userRow);
      return rows.map(({ user_id, username, email: found }) => ({
        userId: user_id,
        username,
        email: found,
      }));
    },

    /**
     * Like {@link findUsersByEmail}, with each user's admin state: every user
     * whose email is `email`, ignoring ASCII case.
     */
    findUserAdminsByEmail: async (
      email: string
    ): Promise<HarborUserAdmin[]> => {
      const rows = await usersByEmail(email, userAdminRow);
      return rows.map(adminOf);
    },

    /**
     * The admin state of the user whose id is `userId`, or `undefined` when
     * there is no such user. It asks the user list with `q=user_id=<id>`,
     * which Harbor's query builder filters on exactly (`user_id` is a column
     * of its user table), and keeps only the row with that id, so a Harbor
     * that ignored the filter would cost pages, not a wrong answer.
     */
    findUserAdminById: async (
      userId: number
    ): Promise<HarborUserAdmin | undefined> => {
      const wanted = idOf("user", userId);
      const rows = paged(api, HARBOR_CALLS.listUsers, (page) =>
        api.read({
          call: HARBOR_CALLS.listUsers,
          path: "/users",
          query: { q: `user_id=${wanted}`, ...pageQuery(page) },
          answer: z.array(userAdminRow),
        })
      );
      for await (const row of rows) {
        if (row.user_id === wanted) return adminOf(row);
      }
      return undefined;
    },

    /**
     * Whether the caller is a Harbor system administrator by its own
     * `sysadmin_flag`, and its user id. Only a caller who is a Harbor user
     * gets a 2xx: a token Harbor doesn't
     * accept 401. The rest of the body, which holds the user's CLI secret in
     * OIDC mode, is dropped by the parse and never logged.
     */
    currentUserAdmin: async (): Promise<{
      userId: number;
      sysadminFlag: boolean;
    }> => {
      const { user_id, sysadmin_flag } = await api.read({
        call: HARBOR_CALLS.currentUser,
        path: "/users/current",
        answer: currentUserRow,
      });
      return { userId: user_id, sysadminFlag: sysadmin_flag };
    },

    /**
     * Sets or clears the user's `sysadmin_flag`. Only a Harbor system
     * administrator may, so this is called as the admin user. Read the user
     * list again to see the result.
     */
    setSysadmin: async (userId: number, sysadmin: boolean): Promise<void> => {
      await api.send({
        call: HARBOR_CALLS.setSysadmin,
        path: `/users/${idOf("user", userId)}/sysadmin`,
        body: { sysadmin_flag: sysadmin },
      });
    },

    /**
     * Every project the caller can see. Harbor answers this for an
     * anonymous caller too, with the public projects, so the credential is
     * proved first: a broken one would otherwise read as a short list.
     */
    listProjects: async (): Promise<HarborProject[]> => {
      await proveCredential();
      return collect(
        paged(api, HARBOR_CALLS.listProjects, async (page) => {
          const rows = await api.read({
            call: HARBOR_CALLS.listProjects,
            path: "/projects",
            query: { ...pageQuery(page), with_detail: "false" },
            answer: z.array(projectRow),
          });
          return rows.map(({ project_id, name }) => ({
            projectId: project_id,
            name,
          }));
        })
      );
    },

    projectExists,

    /**
     * The user's own member row on the project, or `undefined` when they have
     * none. Group rows don't count, even one whose group id equals the user
     * id: P0 manages direct membership only (INT-232). It stops paging on the
     * row. A project that doesn't exist fails with `project_gone`.
     */
    findDirectMember: async (
      project: string,
      userId: number
    ): Promise<HarborMember | undefined> => {
      idOf("user", userId);
      for await (const row of members(project)) {
        if (row.entityType === "u" && row.entityId === userId) return row;
      }
      return undefined;
    },

    /**
     * Adds the user to the project with a direct role. Harbor answers 409
     * when the user has a direct role there already, and 400 when there's no
     * such user. Read the members again to see the result.
     */
    addMember: async (
      project: string,
      { userId, roleId }: { userId: number; roleId: number }
    ): Promise<void> => {
      const call = HARBOR_CALLS.addMember;
      const request = {
        call,
        path: `/projects/${segment(project)}/members`,
        body: {
          role_id: idOf("role", roleId),
          member_user: { user_id: idOf("user", userId) },
        },
      };
      await onProject(project, call, () => api.send(request));
    },

    /**
     * Sets a membership's role. Harbor answers 200 for a member id that
     * isn't the project's, and changes nothing: read the members again to
     * see the result.
     */
    updateMember: async (
      project: string,
      { memberId, roleId }: { memberId: number; roleId: number }
    ): Promise<void> => {
      const call = HARBOR_CALLS.updateMember;
      const request = {
        call,
        path: `/projects/${segment(project)}/members/${idOf("member", memberId)}`,
        body: { role_id: idOf("role", roleId) },
      };
      await onProject(project, call, () => api.send(request));
    },

    /**
     * Removes a membership. Harbor answers 200 for a member id that isn't
     * the project's, and changes nothing: read the members again to see the
     * result.
     */
    removeMember: async (project: string, memberId: number): Promise<void> => {
      const call = HARBOR_CALLS.removeMember;
      const request = {
        call,
        path: `/projects/${segment(project)}/members/${idOf("member", memberId)}`,
      };
      await onProject(project, call, () => api.send(request));
    },
  };
};

export type HarborClient = ReturnType<typeof newHarborClient>;

/**
 * A {@link HarborClient} for the instance, as the Harbor admin user. The
 * admin credential is read from the customer's secret manager and an ID token
 * minted from it now, on every connect, so a rotated secret takes effect on
 * the next call. A connector call connects once, and every Harbor call it
 * makes reuses that token. Fails with the secret read's or the identity
 * provider's `ConnectorError`.
 */
export type ConnectHarbor = (
  instance: Instance,
  logger: Logger
) => Promise<HarborClient>;

/** A {@link HarborClient} for the instance at `url`, with `idToken`. */
export const harborClientFor = ({
  url,
  idToken,
  logger,
}: {
  url: string;
  idToken: string;
  logger: Logger;
}): HarborClient =>
  // `url` is the instance's origin: the instance schema made it so.
  newHarborClient(newHarborApi({ origin: url, idToken, logger }));

export const connectHarbor: ConnectHarbor = async ({ url, secret }, logger) => {
  const credential = await readAdminCredential(secret, logger);
  const idToken = await mintIdToken({
    credential,
    host: hostOf({ url }),
    logger,
  });
  return harborClientFor({ url, idToken, logger });
};
