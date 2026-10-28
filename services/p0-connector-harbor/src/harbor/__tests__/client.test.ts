import { ConnectorError } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ADMIN_CREDENTIAL,
  AUTHORIZATION,
  ID_TOKEN,
  INSTANCE,
  logger,
  propertySeed,
  seededRandom,
} from "../../__tests__/fixtures.ts";
import { readAdminCredential } from "../../secrets.ts";
import { type HarborCall, HarborError, newHarborApi } from "../api.ts";
import {
  HARBOR_CALLS,
  type HarborClient,
  MAX_PAGES,
  PAGE_SIZE,
  connectHarbor,
  foldAsciiCase,
  harborClientFor,
  paged,
} from "../client.ts";
import {
  type FakeHarborState,
  type FakeMember,
  type FakeUser,
  ORIGIN,
  fakeProject,
  memberRow,
  newFakeHarbor,
  sentJson,
} from "./fake-harbor.ts";
import { withProvider } from "./fake-provider.ts";

// The secret manager is `secrets.test.ts`'s business.
vi.mock("../../secrets.ts");

const API = `${ORIGIN}/api/v2.0`;

/** The call that proves the credential. */
const PROOF = `GET ${API}/users?page=1&page_size=1`;

const user = (id: number, email = `user${id}@example.com`): FakeUser => ({
  user_id: id,
  username: `user${id}`,
  email,
});

const state = (overrides: Partial<FakeHarborState> = {}): FakeHarborState => ({
  users: [user(3), user(4)],
  projects: [
    { project_id: 1, name: "library", public: true, members: [] },
    { project_id: 2, name: "team", public: false, members: [] },
  ],
  ...overrides,
});

const client = (idToken = ID_TOKEN) =>
  harborClientFor({ url: ORIGIN, idToken, logger });

/** A token Harbor doesn't accept: it treats the caller as anonymous. */
const ANONYMOUS = "not.the.token";

/** A user who isn't a system administrator, as the token's user. */
const NOT_ADMIN: Partial<FakeHarborState> = {
  users: [user(3), user(4), user(5)],
  caller: 5,
};

/** The {@link HarborError} `run` fails with. Anything else fails the test. */
const harborError = async (run: () => Promise<unknown>) => {
  const outcome = await run().then(
    () => new Error("expected the call to throw"),
    (error: unknown) => error
  );
  if (outcome instanceof HarborError) return outcome;
  throw outcome;
};

const statusOf = async (run: () => Promise<unknown>) => {
  const { failure } = await harborError(run);
  return failure.kind === "status" ? failure.status : failure;
};

const collect = async <T>(rows: AsyncIterable<T>) => {
  const all: T[] = [];
  for await (const row of rows) all.push(row);
  return all;
};

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("connectHarbor", () => {
  it("reads the secret and mints a token on every connect, and calls Harbor with that token only", async () => {
    vi.mocked(readAdminCredential).mockResolvedValue(ADMIN_CREDENTIAL);
    const harbor = withProvider(newFakeHarbor(state()));

    const first = await connectHarbor(INSTANCE, logger);
    await first.proveCredential();
    await first.proveCredential();
    await (await connectHarbor(INSTANCE, logger)).proveCredential();

    expect(readAdminCredential).toHaveBeenCalledTimes(2);
    expect(readAdminCredential).toHaveBeenCalledWith(INSTANCE.secret, logger);
    const calls = harbor.fetch.mock.calls.map(([url]) => String(url));
    // One token per connect, reused by every call made with it.
    expect(calls.filter((url) => url.endsWith("/token"))).toHaveLength(2);
    for (const [url, init] of harbor.fetch.mock.calls) {
      if (!String(url).startsWith(`${API}/`)) continue;
      expect(new Headers(init?.headers).get("authorization")).toBe(
        AUTHORIZATION
      );
    }
  });

  it("fails with the secret read's error, before any call", async () => {
    const refused = new ConnectorError({
      type: "object_not_found",
      message: "no secret",
      payload: { manager: "aws" },
    });
    vi.mocked(readAdminCredential).mockRejectedValue(refused);
    const harbor = newFakeHarbor(state());

    await expect(connectHarbor(INSTANCE, logger)).rejects.toBe(refused);
    expect(harbor.fetch).not.toHaveBeenCalled();
  });

  it("fails with the provider's refusal, before any Harbor call", async () => {
    vi.mocked(readAdminCredential).mockResolvedValue({
      ...ADMIN_CREDENTIAL,
      refreshToken: "revoked",
    });
    const harbor = withProvider(newFakeHarbor(state()));

    const error = await connectHarbor(INSTANCE, logger).catch(
      (thrown: unknown) => thrown
    );

    expect(error).toMatchObject({
      data: { payload: { reason: "admin_signin_expired" } },
    });
    expect(
      harbor.fetch.mock.calls.some(([url]) => String(url).startsWith(API))
    ).toBe(false);
  });
});

describe("systemInfo", () => {
  it("reports the auth mode, and the version Harbor tells the admin user", async () => {
    newFakeHarbor(state());

    await expect(client().systemInfo()).resolves.toEqual({
      authMode: "oidc_auth",
      harborVersion: "v2.14.0-44a74424",
    });
  });

  // From 2.13.0, Harbor keeps the version from a caller it didn't
  // authenticate, and it still answers 200.
  it("answers a credential Harbor doesn't accept, without the version", async () => {
    newFakeHarbor(state());

    await expect(client(ANONYMOUS).systemInfo()).resolves.toEqual({
      authMode: "oidc_auth",
    });
  });
});

describe("proveCredential", () => {
  it("passes when Harbor accepts the token and its user may list users", async () => {
    const harbor = newFakeHarbor(state());

    await client().proveCredential();

    expect(harbor.calls()).toEqual([PROOF]);
  });

  // Harbor treats it as anonymous, which the user list refuses.
  it("fails with 401 when Harbor doesn't accept the credential", async () => {
    newFakeHarbor(state());

    await expect(
      statusOf(() => client(ANONYMOUS).proveCredential())
    ).resolves.toBe(401);
  });

  it("fails with 403 when the token's user isn't a system administrator", async () => {
    newFakeHarbor(state(NOT_ADMIN));

    const error = await harborError(() => client().proveCredential());

    expect(error.failure).toEqual({ kind: "status", status: 403 });
    expect(error.call).toBe(HARBOR_CALLS.listUsers);
  });
});

describe("findUsersByEmail", () => {
  // Harbor's filter is a substring match ignoring case. The client keeps the
  // exact match, wherever it is.
  it("keeps only the users whose email is the one asked for, ignoring case, from every page", async () => {
    const near = Array.from({ length: 150 }, (_, i) =>
      user(i + 10, `jo${i}ann@example.com`)
    );
    const harbor = newFakeHarbor(
      state({
        users: [...near, user(3, "Ann@Example.com"), user(4, "x@other.com")],
      })
    );

    const found = await client().findUsersByEmail("ann@example.com");

    expect(found).toEqual([
      { userId: 3, username: "user3", email: "Ann@Example.com" },
    ]);
    expect(harbor.calls()).toEqual([
      `GET ${API}/users?email=ann%40example.com&page=1&page_size=100`,
      `GET ${API}/users?email=ann%40example.com&page=2&page_size=100`,
    ]);
  });

  it("returns every exact match, so a caller can tell one from several", async () => {
    newFakeHarbor(
      state({
        users: [
          user(3, "ann@example.com"),
          user(4, "joann@example.com"),
          user(5, "ANN@EXAMPLE.COM"),
        ],
      })
    );

    const found = await client().findUsersByEmail("Ann@example.com");

    expect(found.map(({ userId }) => userId)).toEqual([3, 5]);
  });

  // Only ASCII case is ignored: a look-alike that Unicode case folding would
  // turn into the principal's email isn't the principal.
  it.each([
    ["the Kelvin sign", "\u212Aate@example.com", "kate@example.com"],
    ["a long s", "\u017Fam@example.com", "sam@example.com"],
    ["a dotted capital I", "\u0130rene@example.com", "irene@example.com"],
  ])(
    "doesn't match an email that differs by %s",
    async (_case, stored, email) => {
      newFakeHarbor(state({ users: [user(3, stored)] }));

      await expect(client().findUsersByEmail(email)).resolves.toEqual([]);
    }
  );

  it("folds ASCII case only", () => {
    expect(foldAsciiCase("AbC@Example.COM")).toBe("abc@example.com");
    expect(foldAsciiCase("\u212A\u0130\u017F\u00C9")).toBe(
      "\u212A\u0130\u017F\u00C9"
    );
  });

  it("returns no one when no email is exactly it", async () => {
    newFakeHarbor(state({ users: [user(4, "joann@example.com")] }));

    await expect(client().findUsersByEmail("ann@example.com")).resolves.toEqual(
      []
    );
  });

  it("skips a user with no email", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json([{ user_id: 5, username: "ldap-user", email: null }])
      )
    );

    await expect(client().findUsersByEmail("a@b.c")).resolves.toEqual([]);
  });

  // Harbor's emails are at most 255 characters, so a longer one isn't
  // Harbor's, even when it is the one asked for.
  it("fails on a user whose email is longer than Harbor's", async () => {
    const email = `${"a".repeat(250)}@b.example`;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json([{ user_id: 5, username: "someone", email }])
      )
    );

    const error = await harborError(() => client().findUsersByEmail(email));

    expect(error.failure).toEqual({
      kind: "unexpected",
      reason: "wrong_shape",
    });
  });

  // `?email=` with nothing in it matches every user.
  it.each(["", "  "])("refuses the email %j before any call", async (email) => {
    const harbor = newFakeHarbor(state());

    await expect(client().findUsersByEmail(email)).rejects.toBeInstanceOf(
      ConnectorError
    );
    expect(harbor.fetch).not.toHaveBeenCalled();
  });
});

describe("listProjects", () => {
  it("proves the credential, then lists every project, without details, from every page", async () => {
    const projects = Array.from({ length: 101 }, (_, i) => ({
      project_id: i + 1,
      name: `p${i}`,
      public: false,
      members: [],
    }));
    const harbor = newFakeHarbor(state({ projects }));

    const listed = await client().listProjects();

    expect(listed).toHaveLength(101);
    expect(listed[100]).toEqual({ projectId: 101, name: "p100" });
    expect(harbor.calls()).toEqual([
      PROOF,
      `GET ${API}/projects?page=1&page_size=100&with_detail=false`,
      `GET ${API}/projects?page=2&page_size=100&with_detail=false`,
    ]);
  });

  // Harbor answers GET /projects for a credential it doesn't accept, with
  // the public projects. Without the proof that would read as a short list.
  it("fails with 401 for a credential Harbor doesn't accept, and lists nothing", async () => {
    const harbor = newFakeHarbor(state());

    await expect(
      statusOf(() => client(ANONYMOUS).listProjects())
    ).resolves.toBe(401);
    expect(harbor.calls()).toEqual([PROOF]);
  });
});

describe("projectExists", () => {
  it("is true for a project that exists, whether or not the caller may touch it", async () => {
    newFakeHarbor(state(NOT_ADMIN));

    await expect(client().projectExists("team")).resolves.toBe(true);
    await expect(client().projectExists("library")).resolves.toBe(true);
  });

  it("is false for a project that doesn't exist", async () => {
    newFakeHarbor(state());

    await expect(client().projectExists("gone")).resolves.toBe(false);
  });

  it("asks by name, in the query", async () => {
    const harbor = newFakeHarbor(state());

    await client().projectExists("a b");

    expect(harbor.calls()).toEqual([`HEAD ${API}/projects?project_name=a+b`]);
  });

  it("fails on any other answer", async () => {
    newFakeHarbor(state());

    await expect(
      statusOf(() => client(ANONYMOUS).projectExists("library"))
    ).resolves.toBe(401);
  });
});

describe("a project's routes", () => {
  const ROUTES: [
    string,
    (h: HarborClient, project: string) => Promise<unknown>,
  ][] = [
    ["findDirectMember", (h, project) => h.findDirectMember(project, 3)],
    [
      "addMember",
      (h, project) => h.addMember(project, { userId: 3, roleId: 2 }),
    ],
    [
      "updateMember",
      (h, project) => h.updateMember(project, { memberId: 1, roleId: 2 }),
    ],
    ["removeMember", (h, project) => h.removeMember(project, 1)],
  ];

  // Harbor answers 403 for a project that doesn't exist, the same as for a
  // caller who may not touch it.
  it.each(ROUTES)(
    "%s fails with project_gone for a project that doesn't exist",
    async (_route, run) => {
      const harbor = newFakeHarbor(state());

      const error = await harborError(() => run(client(), "gone"));

      expect(error.failure).toEqual({ kind: "project_gone", project: "gone" });
      expect(harbor.calls().at(-1)).toBe(
        `HEAD ${API}/projects?project_name=gone`
      );
    }
  );

  it.each(ROUTES)(
    "%s fails with the 403 for a project the caller may not touch",
    async (_route, run) => {
      newFakeHarbor(state(NOT_ADMIN));

      await expect(statusOf(() => run(client(), "team"))).resolves.toBe(403);
    }
  );

  // A delete can land between Harbor's two lookups of the project.
  it.each(ROUTES)(
    "%s fails with project_gone when Harbor answers 404, without asking again",
    async (_route, run) => {
      const harbor = newFakeHarbor(state({ vanishing: new Set(["team"]) }));

      const error = await harborError(() => run(client(), "team"));

      expect(error.failure).toEqual({ kind: "project_gone", project: "team" });
      expect(harbor.calls().some((call) => call.startsWith("HEAD"))).toBe(
        false
      );
    }
  );

  it("fail with what HEAD answered when it fails too", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init?: RequestInit) =>
        Response.json({}, { status: init?.method === "HEAD" ? 503 : 403 })
      )
    );

    const error = await harborError(() => client().findDirectMember("team", 3));

    expect(error.failure).toEqual({ kind: "status", status: 503 });
    expect(error.call).toBe(HARBOR_CALLS.headProject);
  });

  it.each(["..", "."])(
    "refuse the project name %j before any call",
    async (name) => {
      const harbor = newFakeHarbor(state());

      for (const [, run] of ROUTES) {
        await expect(
          (async () => run(client(), name))()
        ).rejects.toBeInstanceOf(ConnectorError);
      }
      expect(harbor.fetch).not.toHaveBeenCalled();
    }
  );

  // A segment Go's ParseInt takes is an id to Harbor, unless the call says
  // it's a name.
  it("ask for a project by name when its name looks like an id", async () => {
    const harbor = newFakeHarbor(
      state({
        projects: [
          {
            project_id: 1,
            name: "007",
            public: false,
            members: [memberRow(1, 3)],
          },
          {
            project_id: 7,
            name: "seven",
            public: false,
            members: [memberRow(2, 4)],
          },
        ],
      })
    );

    await expect(client().findDirectMember("007", 3)).resolves.toMatchObject({
      entityId: 3,
    });
    const [[url, init] = []] = harbor.fetch.mock.calls;
    expect(url).toBe(`${API}/projects/007/members?page=1&page_size=100`);
    expect(new Headers(init?.headers).get("x-is-resource-name")).toBe("true");
    // Without the header, the same path is project 7's.
    const unnamed = await fetch(String(url), {
      headers: { authorization: AUTHORIZATION },
    });
    expect(await unnamed.json()).toEqual([memberRow(2, 4)]);
  });
});

describe("findDirectMember", () => {
  const rows = (count: number, first = 1) =>
    Array.from({ length: count }, (_, i) =>
      memberRow(first + i, first + i + 1000)
    );
  const team = (members: FakeMember[]) =>
    state({ projects: [fakeProject(1, "team", members)] });

  // X-Total-Count counts more rows than the list returns, so paging that
  // waited for it would never stop.
  it("finds the user's row on page 2, whatever X-Total-Count says", async () => {
    const harbor = newFakeHarbor(team([...rows(100), memberRow(101, 42, 4)]));

    await expect(client().findDirectMember("team", 42)).resolves.toEqual({
      memberId: 101,
      entityId: 42,
      entityType: "u",
      roleId: 4,
    });
    expect(harbor.calls()).toEqual([
      `GET ${API}/projects/team/members?page=1&page_size=100`,
      `GET ${API}/projects/team/members?page=2&page_size=100`,
    ]);
  });

  // Page 2 is full, so only stopping on the row leaves page 3 unread.
  it("stops paging on the user's row", async () => {
    const harbor = newFakeHarbor(
      team([
        ...rows(100, 1),
        ...rows(50, 101),
        memberRow(151, 42, 4),
        ...rows(49, 152),
        ...rows(100, 201),
      ])
    );

    await expect(client().findDirectMember("team", 42)).resolves.toMatchObject({
      memberId: 151,
    });
    expect(harbor.fetch).toHaveBeenCalledTimes(2);
  });

  it("reads every page when the user has no row", async () => {
    const harbor = newFakeHarbor(team(rows(150)));

    await expect(
      client().findDirectMember("team", 42)
    ).resolves.toBeUndefined();
    expect(harbor.fetch).toHaveBeenCalledTimes(2);
  });

  // P0 manages direct membership only (INT-232).
  it("skips a group's row, even one whose group id is the user's id", async () => {
    newFakeHarbor(team([memberRow(1, 3, 1, "g"), memberRow(2, 3, 2, "u")]));

    await expect(client().findDirectMember("team", 3)).resolves.toEqual({
      memberId: 2,
      entityId: 3,
      entityType: "u",
      roleId: 2,
    });
  });

  it("finds nothing when only a group of the same id is a member", async () => {
    newFakeHarbor(team([memberRow(1, 3, 1, "g")]));

    await expect(client().findDirectMember("team", 3)).resolves.toBeUndefined();
  });
});

// With `User: read`, in OIDC mode, a user record holds the user's CLI secret,
// so the connector asks for the status and never takes the body.
describe("member writes", () => {
  const team = (members: FakeMember[] = []) =>
    state({
      projects: [{ project_id: 1, name: "team", public: false, members }],
    });

  it("adds a user with a role", async () => {
    const harbor = newFakeHarbor(team());

    await client().addMember("team", { userId: 3, roleId: 2 });

    const [[url, init] = []] = harbor.fetch.mock.calls;
    expect(`${init?.method} ${url}`).toBe(`POST ${API}/projects/team/members`);
    expect(sentJson(init)).toEqual({
      role_id: 2,
      member_user: { user_id: 3 },
    });
    expect(harbor.state.projects[0]?.members).toEqual([
      { id: 1000, entity_id: 3, entity_type: "u", role_id: 2 },
    ]);
  });

  it("fails with 409 for a user with a direct role there already, and 400 for no such user", async () => {
    newFakeHarbor(team([memberRow(1, 3)]));

    await expect(
      statusOf(() => client().addMember("team", { userId: 3, roleId: 2 }))
    ).resolves.toBe(409);
    await expect(
      statusOf(() => client().addMember("team", { userId: 99, roleId: 2 }))
    ).resolves.toBe(400);
  });

  it("updates a member's role", async () => {
    const harbor = newFakeHarbor(team([memberRow(1, 3, 3)]));

    await client().updateMember("team", { memberId: 1, roleId: 4 });

    const [[url, init] = []] = harbor.fetch.mock.calls;
    expect(`${init?.method} ${url}`).toBe(`PUT ${API}/projects/team/members/1`);
    expect(sentJson(init)).toEqual({ role_id: 4 });
    expect(harbor.state.projects[0]?.members[0]?.role_id).toBe(4);
  });

  it("removes a member", async () => {
    const harbor = newFakeHarbor(team([memberRow(1, 3)]));

    await client().removeMember("team", 1);

    const [[url, init] = []] = harbor.fetch.mock.calls;
    expect(`${init?.method} ${url}`).toBe(
      `DELETE ${API}/projects/team/members/1`
    );
    expect(harbor.state.projects[0]?.members).toEqual([]);
  });

  // Harbor answers 200 and changes nothing: only a re-read shows it.
  it("resolves for a member id that isn't the project's, and nothing changes", async () => {
    const harbor = newFakeHarbor(team([memberRow(1, 3, 3)]));

    await client().updateMember("team", { memberId: 42, roleId: 1 });
    await client().removeMember("team", 42);

    expect(harbor.state.projects[0]?.members).toEqual([memberRow(1, 3, 3)]);
  });

  it.each([
    [
      "role",
      (h: HarborClient) => h.addMember("team", { userId: 3, roleId: 0 }),
    ],
    [
      "user",
      (h: HarborClient) =>
        h.addMember("team", { userId: Number.NaN, roleId: 1 }),
    ],
    [
      "member",
      (h: HarborClient) => h.updateMember("team", { memberId: 1.5, roleId: 1 }),
    ],
    ["member", (h: HarborClient) => h.removeMember("team", -1)],
  ])(
    "refuses a %s id that isn't a positive integer before any call",
    async (_what, run) => {
      const harbor = newFakeHarbor(team());

      await expect(run(client())).rejects.toThrow("isn't a Harbor");
      expect(harbor.fetch).not.toHaveBeenCalled();
    }
  );

  it.each([
    [
      "addMember",
      (h: HarborClient) => h.addMember("team", { userId: 4, roleId: 2 }),
    ],
    [
      "updateMember",
      (h: HarborClient) => h.updateMember("team", { memberId: 1, roleId: 2 }),
    ],
    ["removeMember", (h: HarborClient) => h.removeMember("team", 1)],
  ] as const)(
    "%s fails with 403 when the token's user isn't a system administrator",
    async (_write, run) => {
      newFakeHarbor({ ...team([memberRow(1, 3)]), ...NOT_ADMIN });

      const error = await harborError(() => run(client()));

      expect(error.failure).toEqual({ kind: "status", status: 403 });
    }
  );
});

describe("paged", () => {
  const CALL: HarborCall = HARBOR_CALLS.listMembers;
  const api = () => newHarborApi({ origin: ORIGIN, idToken: ID_TOKEN, logger });

  it("fails on a page longer than it asked for, and logs why", async () => {
    const warn = vi.spyOn(logger, "warn");

    const error = await harborError(() =>
      collect(
        paged(api(), CALL, async () =>
          Array.from({ length: PAGE_SIZE + 1 }, () => 1)
        )
      )
    );

    expect(error.failure).toEqual({
      kind: "unexpected",
      reason: "too_many_rows",
    });
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ route: CALL.route, reason: "too_many_rows" }),
      expect.any(String)
    );
  });

  it("gives up after MAX_PAGES full pages, and logs why", async () => {
    const warn = vi.spyOn(logger, "warn");
    const readPage = vi.fn(async () =>
      Array.from({ length: PAGE_SIZE }, () => 1)
    );

    const error = await harborError(() =>
      collect(paged(api(), CALL, readPage))
    );

    expect(error.failure).toEqual({ kind: "unexpected", reason: "endless" });
    expect(readPage).toHaveBeenCalledTimes(MAX_PAGES);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ route: CALL.route, reason: "endless" }),
      expect.any(String)
    );
  });

  it("reads a short page that comes at MAX_PAGES", async () => {
    const readPage = vi.fn(async (page: number) =>
      Array.from({ length: page === MAX_PAGES ? 5 : PAGE_SIZE }, () => page)
    );

    await expect(collect(paged(api(), CALL, readPage))).resolves.toHaveLength(
      (MAX_PAGES - 1) * PAGE_SIZE + 5
    );
    expect(readPage).toHaveBeenCalledTimes(MAX_PAGES);
  });

  const seed = propertySeed();
  it(
    `reads pages until the first short one, and yields every row once (PROPERTY_SEED=${seed})`,
    // Hundreds of cases, which a loaded machine can take seconds over.
    { timeout: 30_000 },
    async () => {
      const random = seededRandom(seed);
      for (let run = 0; run < 300; run++) {
        const lengths = Array.from(
          { length: 1 + Math.floor(random() * 6) },
          () =>
            random() < 0.6 ? PAGE_SIZE : Math.floor(random() * (PAGE_SIZE + 3))
        );
        const readPage = vi.fn(async (page: number) =>
          Array.from(
            { length: lengths[page - 1] ?? 0 },
            (_, i) => `${page}.${i}`
          )
        );

        const shortAt = lengths.findIndex((length) => length !== PAGE_SIZE);
        const last = shortAt === -1 ? lengths.length : shortAt;
        const outcome = await collect(paged(api(), CALL, readPage)).catch(
          (error: unknown) => error
        );

        expect(readPage).toHaveBeenCalledTimes(last + 1);
        if ((lengths[last] ?? 0) > PAGE_SIZE) {
          expect(outcome).toBeInstanceOf(HarborError);
        } else {
          const expected = lengths
            .slice(0, last + 1)
            .reduce((sum, length) => sum + length, 0);
          expect(outcome).toHaveLength(expected);
          expect(new Set(outcome as string[]).size).toBe(expected);
        }
      }
    }
  );
});

// Harbor's answers are the vendor's bytes. Whatever they hold, the client
// returns what it promises, or fails with a HarborError.
describe("the answers Harbor sends", () => {
  const seed = propertySeed();

  /** Rows whose fields are good, or wrong in one of the ways that matter. */
  const generator = (random: () => number) => {
    const pick = <T>(items: readonly T[]): T => {
      const item = items[Math.floor(random() * items.length)];
      if (item === undefined) throw new Error("picked from no items");
      return item;
    };
    const bad = () =>
      pick([
        () => 0,
        () => -1,
        () => 1.5,
        () => 2 ** 53 + 2,
        () => "7",
        () => "",
        () => "x".repeat(256),
        () => null,
        () => undefined,
        () => [],
        () => ({}),
      ])();
    const good = (name: string) =>
      name.endsWith("id")
        ? Math.floor(random() * 10) + 1
        : name === "entity_type"
          ? "u"
          : `${name}-value`;
    const row = (fields: string[]) =>
      Object.fromEntries(
        fields
          .filter(() => random() < 0.95)
          .map((name) => [name, random() < 0.6 ? good(name) : bad()])
      );
    return { pick, row };
  };

  it(
    `come back from a listing in the promised shape, or fail it (PROPERTY_SEED=${seed})`,
    // Hundreds of cases, which a loaded machine can take seconds over.
    { timeout: 30_000 },
    async () => {
      const random = seededRandom(seed);
      const { pick, row } = generator(random);

      const listings: [string[], (h: HarborClient) => Promise<object[]>][] = [
        [
          ["user_id", "username", "email"],
          (h) => h.findUsersByEmail("email-value"),
        ],
        [["project_id", "name"], (h) => h.listProjects()],
        [
          ["id", "entity_id", "entity_type", "role_id"],
          async (h) => {
            const found = await h.findDirectMember(
              "team",
              1 + Math.floor(random() * 10)
            );
            return found === undefined ? [] : [found];
          },
        ],
      ];

      const isId = (value: unknown) =>
        typeof value === "number" && Number.isSafeInteger(value) && value > 0;
      const promised = (value: object) =>
        Object.entries(value).every(([key, field]) =>
          key === "roleId"
            ? Number.isInteger(field)
            : key.endsWith("Id")
              ? isId(field)
              : typeof field === "string" &&
                field.length <= 255 &&
                (key === "entityType" || field.length > 0)
        );

      for (let i = 0; i < 600; i++) {
        const [fields, list] = pick(listings);
        const page = Array.from({ length: Math.floor(random() * 4) }, () =>
          row(fields)
        );
        vi.stubGlobal(
          "fetch",
          vi.fn(async () => Response.json(random() < 0.1 ? row(fields) : page))
        );

        const outcome = await list(client()).catch((error: unknown) => error);

        if (outcome instanceof HarborError) {
          expect(outcome.failure).toEqual({
            kind: "unexpected",
            reason: "wrong_shape",
          });
        } else {
          expect(Array.isArray(outcome)).toBe(true);
          for (const value of outcome as object[]) {
            expect(promised(value)).toBe(true);
          }
        }
      }
    }
  );

  it(
    `come back from the system info as an auth mode and maybe a version, or fail (PROPERTY_SEED=${seed})`,
    { timeout: 30_000 },
    async () => {
      const random = seededRandom(seed);
      const { row } = generator(random);

      for (let i = 0; i < 300; i++) {
        const body = row(["auth_mode", "harbor_version", "current_time"]);
        vi.stubGlobal(
          "fetch",
          vi.fn(async () => Response.json(random() < 0.1 ? [body] : body))
        );

        const outcome = await client()
          .systemInfo()
          .catch((error: unknown) => error);

        if (outcome instanceof HarborError) {
          expect(outcome.failure).toEqual({
            kind: "unexpected",
            reason: "wrong_shape",
          });
          continue;
        }
        const { authMode, harborVersion, ...rest } = outcome as {
          authMode: unknown;
          harborVersion?: unknown;
        };
        expect(rest).toEqual({});
        expect(typeof authMode === "string" && authMode.length > 0).toBe(true);
        if (harborVersion !== undefined) {
          expect(
            typeof harborVersion === "string" && harborVersion.length > 0
          ).toBe(true);
        }
      }
    }
  );
});

describe("the system administrator calls", () => {
  const json = (body: unknown) => new Response(JSON.stringify(body));

  /** Answers a call with `answer`'s response, or as the fake does. */
  const intercept = (
    harbor: ReturnType<typeof newFakeHarbor>,
    answer: (method: string, url: string) => Response | undefined
  ) => {
    const fake = harbor.fetch.getMockImplementation();
    if (fake === undefined) throw new Error("the fake has no implementation");
    harbor.fetch.mockImplementation(
      async (url, init) => answer(init?.method ?? "GET", url) ?? fake(url, init)
    );
  };

  const asAdmin = () => client();

  const admins = (overrides: Partial<FakeHarborState> = {}) =>
    newFakeHarbor(
      state({
        users: [
          { ...user(3, "ann@example.com"), sysadmin_flag: true },
          user(4, "bob@example.com"),
          { ...user(9, "admin@example.com"), sysadmin_flag: true },
        ],
        caller: 9,
        ...overrides,
      })
    );

  describe("findUserAdminsByEmail", () => {
    it("reads each exact match's admin state from every page", async () => {
      const near = Array.from({ length: 120 }, (_, i) =>
        user(i + 10, `x${i}ann@example.com`)
      );
      const harbor = admins();
      harbor.state.users.push(...near);

      await expect(
        client().findUserAdminsByEmail("ANN@example.com")
      ).resolves.toEqual([
        { userId: 3, sysadminFlag: true, adminRoleInAuth: false },
      ]);
      expect(harbor.calls()).toHaveLength(2);
    });

    it('fails, not reads as "not an admin", when a row has no flag', async () => {
      const harbor = admins();
      intercept(harbor, () =>
        json([{ user_id: 3, username: "u", email: "ann@example.com" }])
      );
      const error = await harborError(() =>
        client().findUserAdminsByEmail("ann@example.com")
      );
      expect(error.failure).toEqual({
        kind: "unexpected",
        reason: "wrong_shape",
      });
    });
  });

  describe("findUserAdminById", () => {
    it("asks for the one user by id, and reads their state", async () => {
      const harbor = admins();
      await expect(client().findUserAdminById(4)).resolves.toEqual({
        userId: 4,
        sysadminFlag: false,
        adminRoleInAuth: false,
      });
      expect(harbor.calls()).toEqual([
        `GET ${API}/users?q=user_id%3D4&page=1&page_size=100`,
      ]);
    });

    it("answers undefined for a user that doesn't exist", async () => {
      admins();
      await expect(client().findUserAdminById(77)).resolves.toBeUndefined();
    });

    // Harbor's query builder skips a key it can't filter on. The answer is
    // still the one user, not the first row.
    it("keeps only the row with the id when Harbor ignores the filter", async () => {
      const harbor = admins();
      intercept(harbor, (_, url) =>
        url.includes("q=user_id")
          ? json(
              [3, 4, 9].map((id) => ({
                user_id: id,
                username: `user${id}`,
                email: null,
                sysadmin_flag: id !== 4,
                admin_role_in_auth: false,
              }))
            )
          : undefined
      );
      await expect(client().findUserAdminById(4)).resolves.toMatchObject({
        userId: 4,
        sysadminFlag: false,
      });
    });

    it("refuses an id that isn't Harbor's before calling", async () => {
      const harbor = admins();
      await expect(client().findUserAdminById(0)).rejects.toThrow(
        "0 isn't a Harbor user id"
      );
      expect(harbor.calls()).toEqual([]);
    });
  });

  describe("currentUserAdmin", () => {
    it("reads the ID token's user and its flag, and nothing else", async () => {
      admins();
      await expect(asAdmin().currentUserAdmin()).resolves.toEqual({
        userId: 9,
        sysadminFlag: true,
      });
    });

    it("answers 401 to a token Harbor doesn't accept", async () => {
      admins({ token: "another.token.x" });
      await expect(statusOf(() => asAdmin().currentUserAdmin())).resolves.toBe(
        401
      );
    });

    it("answers 401 when Harbor doesn't sign users in with OIDC", async () => {
      admins({ authMode: "ldap_auth" });
      await expect(statusOf(() => asAdmin().currentUserAdmin())).resolves.toBe(
        401
      );
    });
  });

  describe("setSysadmin", () => {
    it("sets and clears the flag as an administrator, sending the bearer token", async () => {
      const harbor = admins();
      await asAdmin().setSysadmin(4, true);
      expect(
        harbor.state.users.find(({ user_id }) => user_id === 4)
      ).toMatchObject({
        sysadmin_flag: true,
      });
      await asAdmin().setSysadmin(4, false);
      expect(
        harbor.state.users.find(({ user_id }) => user_id === 4)
      ).toMatchObject({
        sysadmin_flag: false,
      });
      const [url, init] = harbor.fetch.mock.calls[0] ?? [];
      expect(`${init?.method} ${url}`).toBe(`PUT ${API}/users/4/sysadmin`);
      expect(sentJson(init)).toEqual({ sysadmin_flag: true });
      expect(new Headers(init?.headers).get("authorization")).toBe(
        `Bearer ${ID_TOKEN}`
      );
    });

    it("is refused to a user who isn't an administrator", async () => {
      const harbor = admins();
      const admin = harbor.state.users.find(({ user_id }) => user_id === 9);
      if (admin) admin.sysadmin_flag = false;
      await expect(
        statusOf(() => asAdmin().setSysadmin(4, true))
      ).resolves.toBe(403);
    });

    it("answers 404 for a user that doesn't exist", async () => {
      admins();
      await expect(
        statusOf(() => asAdmin().setSysadmin(77, true))
      ).resolves.toBe(404);
    });
  });
});

describe("the user lookups' guards", () => {
  it("skips a user row with no email field at all", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json([{ user_id: 5, username: "no-email" }]))
    );

    await expect(client().findUsersByEmail("a@b.c")).resolves.toEqual([]);
  });

  it("refuses a blank email before any call, saying so", async () => {
    const harbor = newFakeHarbor(state());

    const error = await client()
      .findUserAdminsByEmail("  ")
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ConnectorError);
    expect(error instanceof ConnectorError && error.data).toEqual({
      type: "validation_error",
      message: "The connector needs an email to look a Harbor user up.",
      payload: {},
    });
    expect(harbor.fetch).not.toHaveBeenCalled();
  });

  it("refuses to set the flag on an id that isn't Harbor's, naming it a user id", async () => {
    const harbor = newFakeHarbor(state());

    await expect(client().setSysadmin(0, true)).rejects.toThrow(
      "0 isn't a Harbor user id"
    );
    expect(harbor.fetch).not.toHaveBeenCalled();
  });
});
