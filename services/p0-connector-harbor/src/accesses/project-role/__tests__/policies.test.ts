import { ConnectorError, type Logger } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  AUTHORIZATION,
  HARBOR_HOST,
  ID_TOKEN,
  INSTANCE,
  NEVER_SHOWN,
  connectorError,
  logger,
  recordLogger,
} from "../../../__tests__/fixtures.ts";
import { ALLOWED_EMAIL_DOMAIN_PATTERN_ENV } from "../../../allowlist.ts";
import {
  type FakeHarborState,
  type FakeMember,
  type FakeUser,
  ORIGIN,
  fakeProject,
  memberRow,
  newFakeHarbor,
} from "../../../harbor/__tests__/fake-harbor.ts";
import { type ConnectHarbor, harborClientFor } from "../../../harbor/client.ts";
import {
  ROLES_BY_RANK,
  rankOf,
  roleId,
  roleOf,
} from "../../../harbor/roles.ts";
import type { HarborRole } from "../definition.ts";
import { newProjectRolePrimitives } from "../handler.ts";

const USER_ID = "42";
const EMAIL = "alice@example.com";

const user = (id: number, email: string): FakeUser => ({
  user_id: id,
  username: `user${id}`,
  email,
});

/** A Harbor with alice as user 42, and `members` on the project `team`. */
const harborWith = (
  members: FakeMember[] = [],
  overrides: Partial<FakeHarborState> = {}
) =>
  newFakeHarbor({
    users: [user(42, EMAIL), user(43, "bob@example.com")],
    projects: [fakeProject(2, "team", members)],
    ...overrides,
  });

const connectAs = (idToken = ID_TOKEN) =>
  vi.fn<ConnectHarbor>(async ({ url }, log: Logger) =>
    harborClientFor({ url, idToken, logger: log })
  );

const context = (priorRole: HarborRole | null = null, email = EMAIL) => ({
  ...INSTANCE,
  requestId: "req-1",
  email,
  priorRole,
});

/** Sets the user's role on `team`: a grant with a role, a revoke with `null`. */
const setRole = (
  role: HarborRole | null,
  {
    priorRole = null,
    email = EMAIL,
    connect = connectAs(),
    policies,
  }: {
    priorRole?: HarborRole | null;
    email?: string;
    connect?: ConnectHarbor;
    policies?: { project: string; role: HarborRole | null }[];
  } = {}
) =>
  newProjectRolePrimitives(logger, connect).setPoliciesForUser(
    context(priorRole, email),
    USER_ID,
    { instanceId: "p0-harbor", userId: USER_ID },
    policies ?? [{ project: "team", role }]
  );

/** The user's own row on `team` now, as the fake holds it. */
const ownRow = (harbor: ReturnType<typeof harborWith>) =>
  harbor.state.projects[0]?.members.find(
    (member) => member.entity_type === "u" && member.entity_id === 42
  );

const ownRole = (harbor: ReturnType<typeof harborWith>) => {
  const row = ownRow(harbor);
  return row === undefined ? undefined : roleOf(row.role_id);
};

const writes = (harbor: ReturnType<typeof harborWith>) =>
  harbor.calls().filter((call) => /^(POST|PUT|DELETE) /.test(call));

type Harbor = ReturnType<typeof harborWith>;

/**
 * Answers a call with `answer`'s response when it gives one, and as the
 * fake does otherwise: for the answers a real Harbor gives that the fake
 * can't be set up for.
 */
const intercept = (
  harbor: Harbor,
  answer: (method: string, url: string) => Response | undefined
) => {
  const fake = harbor.fetch.getMockImplementation();
  if (fake === undefined) throw new Error("the fake has no implementation");
  harbor.fetch.mockImplementation(
    async (url, init) => answer(init?.method ?? "GET", url) ?? fake(url, init)
  );
};

const MEMBERS = `${ORIGIN}/api/v2.0/projects/team/members`;

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, "example\\.com");
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("a grant", () => {
  it("adds a user with no direct role, with the role", async () => {
    const harbor = harborWith();

    await setRole("developer");

    expect(ownRow(harbor)).toMatchObject({ role_id: roleId("developer") });
    expect(writes(harbor)).toEqual([`POST ${MEMBERS}`]);
  });

  it("raises a lower direct role", async () => {
    const harbor = harborWith([memberRow(7, 42, roleId("guest"))]);

    await setRole("maintainer");

    expect(ownRole(harbor)).toBe("maintainer");
    expect(writes(harbor)).toEqual([`PUT ${MEMBERS}/7`]);
  });

  it.each<[current: HarborRole, role: HarborRole]>([
    ["developer", "developer"],
    ["projectAdmin", "developer"],
    ["maintainer", "guest"],
  ])(
    "leaves a direct %s alone when granting %s: it never lowers",
    async (current, role) => {
      const harbor = harborWith([memberRow(7, 42, roleId(current))]);

      await setRole(role);

      expect(ownRole(harbor)).toBe(current);
      expect(writes(harbor)).toEqual([]);
    }
  );

  // P0 manages direct membership only (INT-232).
  it("adds the user's own row beside a group row with their id, and leaves the group's alone", async () => {
    const group = memberRow(5, 42, roleId("limitedGuest"), "g");
    const harbor = harborWith([group]);

    await setRole("guest");

    // The fake changes rows in place, so compare with a copy.
    expect(harbor.state.projects[0]?.members).toEqual([
      memberRow(5, 42, roleId("limitedGuest"), "g"),
      expect.objectContaining({
        entity_type: "u",
        entity_id: 42,
        role_id: roleId("guest"),
      }),
    ]);
  });

  describe("when the add doesn't go as asked", () => {
    // A row appeared between the read and the POST.
    it("reads again and raises when the add answers 409", async () => {
      const harbor = harborWith([memberRow(7, 42, roleId("guest"))]);
      let first = true;
      intercept(harbor, (method, url) => {
        if (!first || method !== "GET" || !url.startsWith(MEMBERS)) {
          return undefined;
        }
        first = false;
        return Response.json([]);
      });

      await setRole("developer");

      expect(ownRole(harbor)).toBe("developer");
      expect(writes(harbor)).toEqual([`POST ${MEMBERS}`, `PUT ${MEMBERS}/7`]);
    });

    it("fails, with its own message, when the add answers 409 and the list still shows no row", async () => {
      const harbor = harborWith();
      intercept(harbor, (method) =>
        method === "POST" ? Response.json({}, { status: 409 }) : undefined
      );

      const { data } = await connectorError(() => setRole("developer"));

      expect(data).toEqual({
        type: "dependency_violation",
        message: `Harbor at ${HARBOR_HOST} answered 409 to adding Harbor user 42 to project team, but the member list shows no direct role for them. They may hold a role Harbor doesn't list. Ask a Harbor admin to remove them from the project's Members tab, then retry the grant.`,
        payload: { host: HARBOR_HOST, project: "team", userId: 42 },
      });
      expect(writes(harbor)).toEqual([`POST ${MEMBERS}`]);
    });

    it("fails when the add answers 201 and the list still shows no row", async () => {
      const harbor = harborWith();
      intercept(harbor, (method) =>
        method === "POST" ? new Response(null, { status: 201 }) : undefined
      );

      const { data } = await connectorError(() => setRole("developer"));

      expect(data.type).toBe("dependency_violation");
      expect(data.message).toBe(
        `Harbor at ${HARBOR_HOST} accepted the change to Harbor user 42 on project team, but the project's member list shows no direct role for them. Check the project's Members tab, then retry the grant.`
      );
    });

    // Harbor's answer for a user id it doesn't have.
    it("fails as Harbor's refusal when the add answers 400, and writes nothing more", async () => {
      const harbor = harborWith();
      intercept(harbor, (method) =>
        method === "POST" ? Response.json({}, { status: 400 }) : undefined
      );

      const { data } = await connectorError(() => setRole("developer"));

      expect(data).toEqual({
        type: "validation_error",
        message: `Harbor at ${HARBOR_HOST} refused POST /api/v2.0/projects/{project_name}/members with 400.`,
        payload: { host: HARBOR_HOST, status: 400 },
      });
      expect(writes(harbor)).toEqual([`POST ${MEMBERS}`]);
    });
  });

  describe("reads the row back after a raise", () => {
    // Harbor answers 200 to a PUT on a member id that isn't the project's.
    it("fails when Harbor didn't apply it", async () => {
      const harbor = harborWith([memberRow(7, 42, roleId("guest"))]);
      intercept(harbor, (method) =>
        method === "PUT" ? new Response(null, { status: 200 }) : undefined
      );

      const { data } = await connectorError(() => setRole("maintainer"));

      expect(data.type).toBe("dependency_violation");
      expect(data.message).toBe(
        `Harbor at ${HARBOR_HOST} accepted the change to Harbor user 42 on project team, but the project's member list shows the role guest, not maintainer. Check the project's Members tab, then retry the grant.`
      );
    });

    it("fails when the row is gone", async () => {
      const harbor = harborWith([memberRow(7, 42, roleId("guest"))]);
      intercept(harbor, (method) => {
        if (method !== "PUT") return undefined;
        const [project] = harbor.state.projects;
        if (project) project.members = [];
        return new Response(null, { status: 200 });
      });

      const { data } = await connectorError(() => setRole("maintainer"));

      expect(data.type).toBe("dependency_violation");
      expect(data.message).toContain("shows no direct role for them");
    });

    it("fails, naming the id, when the row holds a role id that isn't one of Harbor's", async () => {
      const harbor = harborWith([memberRow(7, 42, roleId("guest"))], {
        listsUnknownRoles: true,
      });
      intercept(harbor, (method) => {
        if (method !== "PUT") return undefined;
        const row = ownRow(harbor);
        if (row) row.role_id = 9;
        return new Response(null, { status: 200 });
      });

      const { data } = await connectorError(() => setRole("maintainer"));

      expect(data.type).toBe("validation_error");
      expect(data.payload).toMatchObject({ roleId: 9 });
    });
  });

  describe("checks who it grants to", () => {
    it("refuses an email outside the allowed domains before it reads the secret", async () => {
      const harbor = harborWith();
      const connect = connectAs();

      const { data } = await connectorError(() =>
        setRole("developer", { email: "alice@other.com", connect })
      );

      expect(data.payload).toEqual({ reason: "domain_not_allowed" });
      expect(connect).not.toHaveBeenCalled();
      expect(harbor.fetch).not.toHaveBeenCalled();
    });

    it.each<[when: string, email: string, foundUserId: number | null]>([
      ["no Harbor user has the email", "carol@example.com", null],
      ["the email is another user's now", "bob@example.com", 43],
    ])(
      "refuses when %s, with INT-231's copy, and logs the id it found",
      async (_case, email, foundUserId) => {
        const log = recordLogger();
        const harbor = harborWith();

        const { data } = await connectorError(() =>
          setRole("developer", { email })
        );

        expect(data).toEqual({
          type: "validation_error",
          message: `The Harbor user for ${email} on ${HARBOR_HOST} no longer exists, or its email changed. Request access again.`,
          payload: { host: HARBOR_HOST, userId: 42, reason: "no_user" },
        });
        expect(writes(harbor)).toEqual([]);
        expect(log.lines()).toContainEqual([
          { foundUserId },
          "the email no longer resolves to the user the grant is for; refusing",
        ]);
      }
    );

    it("refuses an email two Harbor users have", async () => {
      const harbor = harborWith([], {
        users: [user(42, EMAIL), user(44, "ALICE@example.com")],
      });

      const { data } = await connectorError(() => setRole("developer"));

      expect(data.payload).toEqual({
        host: HARBOR_HOST,
        userIds: "42,44",
        reason: "duplicate_email",
      });
      expect(writes(harbor)).toEqual([]);
    });
  });

  it("refuses a project that no longer exists", async () => {
    harborWith();

    const { data } = await connectorError(() =>
      setRole("developer", {
        policies: [{ project: "gone", role: "developer" }],
      })
    );

    expect(data.payload).toMatchObject({ reason: "project_gone" });
  });

  // Every Harbor call is the admin account's, so a grant surfaces its
  // refusals too.
  it("says the admin account isn't an administrator when Harbor answers 403", async () => {
    const harbor = harborWith([]);
    harbor.state.users.push({
      user_id: 99,
      username: "plain",
      email: "plain@example.com",
    });
    harbor.state.caller = 99;

    const { data } = await connectorError(() => setRole("developer"));

    expect(data.payload).toMatchObject({ reason: "admin_not_harbor_admin" });
    expect(writes(harbor)).toEqual([]);
  });

  it("says Harbor didn't accept the token on a 401", async () => {
    const harbor = harborWith([]);

    const { data } = await connectorError(() =>
      setRole("developer", { connect: connectAs("stale.token.x") })
    );

    expect(data.payload).toMatchObject({ reason: "admin_token_rejected" });
    expect(writes(harbor)).toEqual([]);
  });

  it("passes on the provider's refusal of the refresh token from connecting", async () => {
    harborWith([]);
    const expired = new ConnectorError({
      type: "validation_error",
      message: "sign in again",
      payload: { reason: "admin_signin_expired" },
    });
    const connect = vi.fn<ConnectHarbor>(async () => {
      throw expired;
    });

    await expect(setRole("developer", { connect })).rejects.toBe(expired);
    await expect(setRole(null, { connect })).rejects.toBe(expired);
  });
});

describe("a revoke", () => {
  it("removes the user when they held no role before the grant", async () => {
    const harbor = harborWith([memberRow(7, 42, roleId("developer"))]);

    await setRole(null, { priorRole: null });

    expect(ownRow(harbor)).toBeUndefined();
    expect(writes(harbor)).toEqual([`DELETE ${MEMBERS}/7`]);
  });

  it("puts back a prior role that ranks below the current one", async () => {
    const harbor = harborWith([memberRow(7, 42, roleId("maintainer"))]);

    await setRole(null, { priorRole: "guest" });

    expect(ownRole(harbor)).toBe("guest");
    expect(writes(harbor)).toEqual([`PUT ${MEMBERS}/7`]);
  });

  // A1: a revoke only ever lowers.
  it.each<[current: HarborRole, priorRole: HarborRole]>([
    ["developer", "developer"],
    ["developer", "projectAdmin"],
    ["limitedGuest", "guest"],
  ])(
    "leaves a direct %s alone when the prior role is %s: it never raises",
    async (current, priorRole) => {
      const harbor = harborWith([memberRow(7, 42, roleId(current))]);

      await setRole(null, { priorRole });

      expect(ownRole(harbor)).toBe(current);
      expect(writes(harbor)).toEqual([]);
    }
  );

  // Removing access never depends on the allowlist or the user's email.
  it("checks neither the email's domain nor who has it", async () => {
    vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, undefined);
    const harbor = harborWith([memberRow(7, 42, roleId("developer"))], {
      users: [],
    });

    await setRole(null, { email: "alice@other.com" });

    expect(ownRow(harbor)).toBeUndefined();
    expect(harbor.calls().some((call) => call.includes("/users"))).toBe(false);
  });

  it.each<[what: string, rows: FakeMember[]]>([
    ["no direct row", []],
    ["only a group's row", [memberRow(5, 42, roleId("limitedGuest"), "g")]],
  ])("is done, changing nothing, when the user has %s", async (_case, rows) => {
    const before = structuredClone(rows);
    const harbor = harborWith(rows);

    await setRole(null, { priorRole: "guest" });

    expect(writes(harbor)).toEqual([]);
    expect(harbor.state.projects[0]?.members).toEqual(before);
  });

  describe("reads the row back after a write", () => {
    // Harbor answers 200 to a PUT or DELETE on a member id that isn't the
    // project's.
    it("fails when Harbor didn't remove the user", async () => {
      const harbor = harborWith([memberRow(7, 42, roleId("developer"))]);
      intercept(harbor, (method) =>
        method === "DELETE" ? new Response(null, { status: 200 }) : undefined
      );

      const { data } = await connectorError(() => setRole(null));

      expect(data.type).toBe("dependency_violation");
      expect(data.message).toBe(
        `Harbor at ${HARBOR_HOST} accepted the change to Harbor user 42 on project team, but the project's member list shows them still a direct member. Check the project's Members tab, then retry the revoke.`
      );
    });

    it("fails when Harbor didn't put the prior role back", async () => {
      const harbor = harborWith([memberRow(7, 42, roleId("maintainer"))]);
      intercept(harbor, (method) =>
        method === "PUT" ? new Response(null, { status: 200 }) : undefined
      );

      const { data } = await connectorError(() =>
        setRole(null, { priorRole: "guest" })
      );

      expect(data.type).toBe("dependency_violation");
      expect(data.message).toBe(
        `Harbor at ${HARBOR_HOST} accepted the change to Harbor user 42 on project team, but the project's member list shows the role maintainer, not the prior role guest. Check the project's Members tab, then retry the revoke.`
      );
    });
  });

  describe("a project that no longer exists", () => {
    it("is done, once Harbor itself says the project is gone", async () => {
      const harbor = harborWith();

      await expect(
        setRole(null, { policies: [{ project: "gone", role: null }] })
      ).resolves.toBeUndefined();
      // Harbor answered as Harbor, and its HEAD says there's no such project.
      expect(harbor.calls()).toContain(`GET ${ORIGIN}/api/v2.0/systeminfo`);
      expect(writes(harbor)).toEqual([]);
    });

    // A proxy, or an ingress's default backend. "Already revoked" would
    // leave the access in place.
    it("rejects when everything answers 404", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => Response.json({}, { status: 404 }))
      );

      const { data } = await connectorError(() =>
        setRole(null, { priorRole: "guest" })
      );

      expect(data.type).toBe("validation_error");
      expect(data.message).toContain("the way Harbor does");
    });

    it.each<[write: string, priorRole: HarborRole | null]>([
      ["PUT", "guest"],
      ["DELETE", null],
    ])(
      "rejects when the %s answers 404 while the project exists",
      async (write, priorRole) => {
        const harbor = harborWith([memberRow(7, 42, roleId("maintainer"))]);
        intercept(harbor, (method) =>
          method === write ? Response.json({}, { status: 404 }) : undefined
        );

        const { data } = await connectorError(() =>
          setRole(null, { priorRole })
        );

        expect(data).toEqual({
          type: "dependency_violation",
          message: `Harbor at ${HARBOR_HOST} answered that project team doesn't exist while P0 was taking back Harbor user 42's role, but the project exists. Check the project's Members tab, then retry the revoke.`,
          payload: { host: HARBOR_HOST, project: "team", userId: 42 },
        });
        expect(ownRole(harbor)).toBe("maintainer");
      }
    );
  });
});

// Harbor stores any role id a PUT sends. Its member list is believed to
// leave such a row out (INT-265's research, read from source, not checked
// live): the fake's default. `listsUnknownRoles` is a Harbor that shows it,
// such as a later one with a sixth role.
describe("a member row whose role id isn't one of Harbor's five", () => {
  describe("when Harbor's list leaves it out, as it is believed to", () => {
    it("a grant fails on the 409, with the message for it, and changes nothing", async () => {
      const harbor = harborWith([memberRow(7, 42, 9)]);

      const { data } = await connectorError(() => setRole("developer"));

      expect(data.type).toBe("dependency_violation");
      expect(data.message).toContain("answered 409 to adding Harbor user 42");
      expect(harbor.state.projects[0]?.members).toEqual([memberRow(7, 42, 9)]);
    });

    // The connector can't see the row, so it can't do better.
    it("a revoke finds no row, and reports it done", async () => {
      const harbor = harborWith([memberRow(7, 42, 9)]);

      await setRole(null, { priorRole: "guest" });

      expect(writes(harbor)).toEqual([]);
      expect(harbor.state.projects[0]?.members).toEqual([memberRow(7, 42, 9)]);
    });
  });

  describe("when Harbor's list shows it", () => {
    const shown = () =>
      harborWith([memberRow(7, 42, 9)], { listsUnknownRoles: true });

    it("a grant refuses it, changing nothing", async () => {
      const harbor = shown();

      const { data } = await connectorError(() => setRole("developer"));

      expect(data).toEqual({
        type: "validation_error",
        message: `Harbor user 42 holds role id 9 on project team on ${HARBOR_HOST}, which isn't one of Harbor's project roles. Ask a Harbor admin to set the user's role on the project's Members tab, then retry the grant.`,
        payload: {
          host: HARBOR_HOST,
          project: "team",
          userId: "42",
          roleId: 9,
        },
      });
      expect(writes(harbor)).toEqual([]);
    });

    // P0 can't tell whether the prior role ranks below it.
    it("a revoke with a prior role refuses it, changing nothing", async () => {
      const harbor = shown();

      const { data } = await connectorError(() =>
        setRole(null, { priorRole: "guest" })
      );

      expect(data).toEqual({
        type: "dependency_violation",
        message: `Harbor user 42 holds role id 9 on project team on ${HARBOR_HOST}, which isn't one of Harbor's project roles, so P0 can't put their prior role back. Ask a Harbor admin to set the user's role on the project's Members tab, then retry the revoke.`,
        payload: {
          host: HARBOR_HOST,
          project: "team",
          userId: "42",
          roleId: 9,
        },
      });
      expect(writes(harbor)).toEqual([]);
    });

    // A1: with no prior role the member goes, whatever they hold.
    it("a revoke with no prior role removes the user", async () => {
      const harbor = shown();

      await setRole(null, { priorRole: null });

      expect(harbor.state.projects[0]?.members).toEqual([]);
    });
  });
});

describe("the policies P0 sends", () => {
  it.each<
    [count: string, policies: { project: string; role: HarborRole | null }[]]
  >([
    ["none", []],
    [
      "two",
      [
        { project: "team", role: "guest" },
        { project: "library", role: null },
      ],
    ],
  ])("refuses %s, as a P0 bug", async (_case, policies) => {
    const harbor = harborWith();

    const { data } = await connectorError(() => setRole("guest", { policies }));

    expect(data.type).toBe("unknown");
    expect(harbor.fetch).not.toHaveBeenCalled();
  });
});

describe("what it logs and throws", () => {
  const CASES: [what: string, run: () => Promise<unknown>][] = [
    ["a grant", () => setRole("developer")],
    ["a raise", () => setRole("projectAdmin")],
    ["a revoke", () => setRole(null, { priorRole: "guest" })],
    [
      "a refused identity",
      () => setRole("developer", { email: "bob@example.com" }),
    ],
    [
      "a 401 for the token",
      () => {
        vi.stubGlobal(
          "fetch",
          vi.fn(async () => Response.json({}, { status: 401 }))
        );
        return setRole("developer");
      },
    ],
  ];

  // The request's own logger makes every line, the allowlist's and the
  // client's included, and it is bound to no email.
  it.each(CASES)(
    "carries no credential, and logs no email, on %s",
    async (_case, run) => {
      const log = recordLogger();
      harborWith([memberRow(7, 42, roleId("maintainer"))]);

      const outcome = await run().catch((error: unknown) => error);

      const seen = log.seen(outcome);
      for (const marker of [...NEVER_SHOWN, AUTHORIZATION]) {
        expect(seen).not.toContain(marker);
      }
      expect(log.seen()).not.toContain("alice@");
      expect(log.seen()).not.toContain("bob@");
    }
  );
});

// Every combination: the user's direct role now (none, each of the five, an
// id that isn't one of them, on a Harbor that lists it), a group row with
// their id or not, the prior role (none or each of the five) and the policy
// (a revoke or each of the five): 7 x 2 x 6 x 6 = 504.
describe("over every combination of roles", () => {
  const ROLES: readonly (HarborRole | null)[] = [null, ...ROLES_BY_RANK];
  const CURRENT: readonly (HarborRole | "unknown" | null)[] = [
    ...ROLES,
    "unknown",
  ];

  /** What the user's own row must hold afterwards, or that the call refuses. */
  const expectedFor = (
    current: HarborRole | "unknown" | null,
    priorRole: HarborRole | null,
    role: HarborRole | null
  ): { now: HarborRole | "unknown" | null; refused: boolean } => {
    if (role !== null) {
      // A grant: exactly the role, unless they hold as much or more.
      if (current === "unknown") return { now: "unknown", refused: true };
      return {
        now:
          current === null || rankOf(current) < rankOf(role) ? role : current,
        refused: false,
      };
    }
    // A revoke.
    if (current === null) return { now: null, refused: false };
    if (priorRole === null) return { now: null, refused: false };
    if (current === "unknown") return { now: "unknown", refused: true };
    return {
      now: rankOf(priorRole) < rankOf(current) ? priorRole : current,
      refused: false,
    };
  };

  it(
    "a grant leaves exactly the higher role, a revoke exactly the lower, and a group row never changes",
    { timeout: 60_000 },
    async () => {
      let combinations = 0;
      for (const current of CURRENT) {
        for (const withGroup of [false, true]) {
          for (const priorRole of ROLES) {
            for (const role of ROLES) {
              combinations += 1;
              // A low role, so a change to the group's row would show.
              const group = memberRow(5, 42, roleId("limitedGuest"), "g");
              const harbor = harborWith(
                [
                  ...(withGroup ? [group] : []),
                  ...(current === null
                    ? []
                    : [
                        memberRow(
                          7,
                          42,
                          current === "unknown" ? 9 : roleId(current)
                        ),
                      ]),
                ],
                { listsUnknownRoles: true }
              );
              // The fake changes rows in place: compare with a copy.
              const groupBefore = structuredClone(group);

              const refused = await setRole(role, { priorRole }).then(
                () => false,
                () => true
              );

              const row = ownRow(harbor);
              const now =
                row === undefined ? null : (roleOf(row.role_id) ?? "unknown");
              const groupsNow = harbor.state.projects[0]?.members.filter(
                ({ entity_type }) => entity_type === "g"
              );
              const got = JSON.stringify({ now, refused });
              const expected = JSON.stringify(
                expectedFor(current, priorRole, role)
              );
              if (
                got !== expected ||
                JSON.stringify(groupsNow) !==
                  JSON.stringify(withGroup ? [groupBefore] : [])
              ) {
                throw new Error(
                  `expected ${expected}, got ${got}, groups ${JSON.stringify(groupsNow)} for ${JSON.stringify({ current, withGroup, priorRole, role })}`
                );
              }
              vi.unstubAllGlobals();
            }
          }
        }
      }
      expect(combinations).toBe(504);
    }
  );
});
