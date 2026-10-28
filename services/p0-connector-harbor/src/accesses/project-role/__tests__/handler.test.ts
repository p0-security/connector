import {
  ConnectorError,
  type Logger,
  type ResourceRootSchemaOf,
} from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ADMIN_CREDENTIAL,
  AUTHORIZATION,
  HARBOR_HOST,
  ID_TOKEN,
  INSTANCE,
  NEVER_SHOWN,
  connectorError,
  logger,
  propertySeed,
  recordLogger,
  seededRandom,
} from "../../../__tests__/fixtures.ts";
import { ALLOWED_EMAIL_DOMAIN_PATTERN_ENV } from "../../../allowlist.ts";
import {
  type FakeHarborState,
  type FakeMember,
  type FakeProject,
  type FakeUser,
  ORIGIN,
  fakeProject,
  memberRow,
  newFakeHarbor,
} from "../../../harbor/__tests__/fake-harbor.ts";
import { withProvider } from "../../../harbor/__tests__/fake-provider.ts";
import {
  type ConnectHarbor,
  foldAsciiCase,
  harborClientFor,
} from "../../../harbor/client.ts";
import { roleOf } from "../../../harbor/roles.ts";
import { harborRefusalReason } from "../../../refusals.ts";
import { connectorRouter } from "../../../router.ts";
import { readAdminCredential } from "../../../secrets.ts";
import type { spec } from "../definition.ts";
import { newProjectRolePrimitives } from "../handler.ts";

type ProjectRoleListerQuery = ResourceRootSchemaOf<typeof spec>["ListerQuery"];

// The secret manager is `secrets.test.ts`'s business. Only the router's own
// connect reads it here.
vi.mock("../../../secrets.ts");

const PATTERN = "example\\.com";

const user = (id: number, email: string): FakeUser => ({
  user_id: id,
  username: `user${id}`,
  email,
});

const state = (users: FakeUser[]): FakeHarborState => ({
  users,
  projects: [],
});

/** Connects with a token, without the secret manager, and counts connects. */
const connectAs = (idToken = ID_TOKEN) =>
  vi.fn<ConnectHarbor>(async ({ url }, log: Logger) =>
    harborClientFor({ url, idToken, logger: log })
  );

/** A token Harbor doesn't accept. */
const STALE = "stale.token.x";

/** `base`, with the token signing in as a user who isn't an administrator. */
const notAdmin = (base: FakeHarborState): FakeHarborState => ({
  ...base,
  users: [...base.users, user(99, "plain@example.com")],
  caller: 99,
});

const listMember = (
  email: string,
  connect: ConnectHarbor = connectAs(),
  log: Logger = logger
) =>
  newProjectRolePrimitives(log, connect).list({
    type: "member",
    context: INSTANCE,
    email,
  });

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, PATTERN);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("the member lister", () => {
  it("returns the Harbor user whose email is the principal's, as its id and username", async () => {
    const harbor = newFakeHarbor(
      state([user(3, "alice@example.com"), user(4, "bob@example.com")])
    );

    await expect(listMember("alice@example.com")).resolves.toEqual([
      { key: "3", value: "user3" },
    ]);
    expect(harbor.calls()).toEqual([
      `GET ${ORIGIN}/api/v2.0/users?email=alice%40example.com&page=1&page_size=100`,
    ]);
  });

  // Harbor stores an email as the IdP sent it the first time.
  it("matches the email ignoring case", async () => {
    newFakeHarbor(state([user(3, "Alice@Example.com")]));

    await expect(listMember("alice@EXAMPLE.com")).resolves.toEqual([
      { key: "3", value: "user3" },
    ]);
  });

  it("returns nothing when no Harbor user has the email", async () => {
    newFakeHarbor(state([user(3, "bob@example.com")]));

    await expect(listMember("alice@example.com")).resolves.toEqual([]);
  });

  // Harbor's `?email=` is a substring match.
  it("returns nothing when Harbor's users only contain the email", async () => {
    newFakeHarbor(
      state([user(3, "malice@example.com"), user(4, "alice@example.com.au")])
    );

    await expect(listMember("alice@example.com")).resolves.toEqual([]);
  });

  it("returns nothing for bob@example.com when Harbor only has jimbob@example.com", async () => {
    const harbor = newFakeHarbor(state([user(3, "jimbob@example.com")]));

    await expect(listMember("bob@example.com")).resolves.toEqual([]);
    // Harbor did offer the near miss: the connector dropped it.
    expect(harbor.calls()).toHaveLength(1);
  });

  it("finds the user behind a full page of near matches", async () => {
    const near = Array.from({ length: 100 }, (_, i) =>
      user(i + 10, `x${i}alice@example.com`)
    );
    const harbor = newFakeHarbor(
      state([...near, user(3, "alice@example.com")])
    );

    await expect(listMember("alice@example.com")).resolves.toEqual([
      { key: "3", value: "user3" },
    ]);
    expect(harbor.fetch).toHaveBeenCalledTimes(2);
  });

  // Harbor's unique constraint on emails is case-sensitive.
  it("refuses an email two Harbor users have, as INT-231 words it", async () => {
    newFakeHarbor(
      state([user(3, "alice@example.com"), user(4, "Alice@example.com")])
    );

    const { data } = await connectorError(() =>
      listMember("alice@example.com")
    );

    expect(data).toEqual({
      type: "validation_error",
      message: `More than one Harbor user on ${HARBOR_HOST} has the email alice@example.com. Ask a Harbor admin to remove the duplicate.`,
      payload: {
        host: HARBOR_HOST,
        userIds: "3,4",
        reason: "duplicate_email",
      },
    });
  });

  describe("the domain allowlist", () => {
    it("refuses an email outside the allowed domains before it reads the secret or calls Harbor", async () => {
      const harbor = newFakeHarbor(state([user(3, "alice@other.com")]));
      const connect = connectAs();

      const { data } = await connectorError(() =>
        listMember("alice@other.com", connect)
      );

      expect(data).toEqual({
        type: "validation_error",
        message:
          "alice@other.com isn't in an email domain this Harbor connector allows.",
        payload: { reason: "domain_not_allowed" },
      });
      expect(connect).not.toHaveBeenCalled();
      expect(harbor.fetch).not.toHaveBeenCalled();
    });

    it("refuses every email while the pattern is unset, before it reads the secret", async () => {
      vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, undefined);
      const harbor = newFakeHarbor(state([user(3, "alice@example.com")]));
      const connect = connectAs();

      const { data } = await connectorError(() =>
        listMember("alice@example.com", connect)
      );

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({ reason: "domain_pattern_unusable" });
      expect(connect).not.toHaveBeenCalled();
      expect(harbor.fetch).not.toHaveBeenCalled();
    });
  });

  describe("when Harbor or the secret fails", () => {
    // Harbor treats a token it doesn't accept as anonymous, and the user
    // list refuses an anonymous caller: the lookup proves the token.
    it("says Harbor didn't accept the token", async () => {
      newFakeHarbor(state([user(3, "alice@example.com")]));

      const { data } = await connectorError(() =>
        listMember("alice@example.com", connectAs(STALE))
      );

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({
        host: HARBOR_HOST,
        status: 401,
        reason: "admin_token_rejected",
      });
    });

    it("says the admin account isn't an administrator when Harbor answers 403", async () => {
      newFakeHarbor(notAdmin(state([user(3, "alice@example.com")])));

      const { data } = await connectorError(() =>
        listMember("alice@example.com")
      );

      expect(data).toEqual({
        type: "validation_error",
        message: `The admin account the connector signs in to Harbor at ${HARBOR_HOST} with isn't a Harbor system administrator. Make it one on Harbor's Users page.`,
        payload: {
          host: HARBOR_HOST,
          status: 403,
          reason: "admin_not_harbor_admin",
        },
      });
    });

    it("passes the secret read's error on, and calls nothing", async () => {
      const refused = new ConnectorError({
        type: "object_not_found",
        message: "no secret",
        payload: { manager: "aws" },
      });
      const harbor = newFakeHarbor(state([]));

      await expect(
        listMember(
          "alice@example.com",
          vi.fn<ConnectHarbor>(async () => {
            throw refused;
          })
        )
      ).rejects.toBe(refused);
      expect(harbor.fetch).not.toHaveBeenCalled();
    });

    it("says Harbor didn't answer", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => {
          throw new TypeError("fetch failed", {
            cause: Object.assign(new Error("refused"), {
              code: "ECONNREFUSED",
            }),
          });
        })
      );

      const { data } = await connectorError(() =>
        listMember("alice@example.com")
      );

      expect(data.type).toBe("upstream_unavailable");
      expect(data.payload).toEqual({ host: HARBOR_HOST });
    });
  });

  describe("what it logs and throws", () => {
    // Each sets Harbor up, as the fake or a stub. The credential is always
    // the sentinel token, so a leak would show its marker.
    const OUTCOMES: [string, () => void, string][] = [
      [
        "one match",
        () => newFakeHarbor(state([user(3, "alice@example.com")])),
        "alice@example.com",
      ],
      [
        "two matches",
        () =>
          newFakeHarbor(
            state([user(3, "alice@example.com"), user(4, "ALICE@example.com")])
          ),
        "alice@example.com",
      ],
      ["a refused domain", () => newFakeHarbor(state([])), "alice@other.com"],
      [
        "a 401",
        () =>
          vi.stubGlobal(
            "fetch",
            vi.fn(async () => Response.json({}, { status: 401 }))
          ),
        "alice@example.com",
      ],
      [
        "a 403",
        () => newFakeHarbor(notAdmin(state([user(3, "alice@example.com")]))),
        "alice@example.com",
      ],
      [
        "no answer, quoting the request",
        () =>
          vi.stubGlobal(
            "fetch",
            vi.fn(async () => {
              throw new TypeError(`fetch failed ${AUTHORIZATION}`, {
                cause: Object.assign(new Error(`refused ${ID_TOKEN}`), {
                  code: "ECONNREFUSED",
                }),
              });
            })
          ),
        "alice@example.com",
      ],
    ];

    it.each(OUTCOMES)(
      "carries no credential, and logs no email, on %s",
      async (_case, setUp, email) => {
        const log = recordLogger();
        setUp();

        const outcome = await listMember(email).catch(
          (error: unknown) => error
        );

        const seen = log.seen(outcome);
        for (const marker of [
          ...NEVER_SHOWN,
          AUTHORIZATION.replace("Basic ", ""),
        ]) {
          expect(seen).not.toContain(marker);
        }
        expect(log.seen()).not.toContain(email);
      }
    );
  });

  // Emails built to sit near the principal: the same, another case, a
  // Unicode look-alike (the Kelvin sign, a long s, a dotted capital I), one
  // character more on either side, or another domain. The model is INT-231's
  // rule: the allowlist first, then the users whose email equals the
  // principal's, ignoring ASCII case only.
  const seed = propertySeed();
  it(
    `returns exactly the one user whose email is the principal's, and refuses the rest (PROPERTY_SEED=${seed})`,
    // Hundreds of cases, which a loaded machine can take seconds over.
    { timeout: 30_000 },
    async () => {
      const random = seededRandom(seed);
      const pick = <T>(items: readonly T[]): T => {
        const item = items[Math.floor(random() * items.length)];
        if (item === undefined) throw new Error("picked from no items");
        return item;
      };
      const LOOK_ALIKES: Record<string, string> = {
        k: "\u212A",
        K: "\u212A",
        s: "\u017F",
        i: "\u0130",
      };
      const lookAlike = (text: string) =>
        [...text].map((c) => LOOK_ALIKES[c] ?? c).join("");
      const flipCase = (text: string) =>
        [...text]
          .map((c) => (random() < 0.5 ? c.toUpperCase() : c.toLowerCase()))
          .join("");

      for (let i = 0; i < 300; i++) {
        const local = Array.from({ length: Math.floor(random() * 4) }, () =>
          pick([
            "a",
            "k",
            "K",
            "s",
            "i",
            "\u212A",
            "\u017F",
            "\u0130",
            ".",
            "-",
          ])
        ).join("");
        const domain = pick(["example.com", "Example.COM", "other.com", ""]);
        const principal = `${local}@${domain}`;
        const near = (): string =>
          pick([
            () => principal,
            () => flipCase(principal),
            () => lookAlike(principal),
            () => `x${principal}`,
            () => `${principal}x`,
            () => `${local}@other.com`,
          ])();
        let id = 10;
        const users = Array.from({ length: Math.floor(random() * 4) }, () =>
          user(id++, near())
        );
        // Now and then, the principal's row comes after a full page.
        if (random() < 0.1) {
          users.unshift(
            ...Array.from({ length: 100 }, () => user(id++, `x${principal}`))
          );
        }
        const harbor = newFakeHarbor(state(users));
        const connect = connectAs();

        const allowed = local !== "" && domain.toLowerCase() === "example.com";
        const matches = users.filter(
          ({ email }) => foldAsciiCase(email) === foldAsciiCase(principal)
        );
        const where = `${JSON.stringify(principal)} among ${JSON.stringify(
          users.map(({ email }) => email).slice(-4)
        )}`;

        const outcome = await listMember(principal, connect).catch(
          (error: unknown) => error
        );

        const reason =
          outcome instanceof ConnectorError
            ? outcome.data.payload.reason
            : undefined;
        // Every refusal carries a reason from the closed set (A17).
        if (
          outcome instanceof Error &&
          !harborRefusalReason.safeParse(reason).success
        ) {
          throw new Error(
            `a refusal without a known reason (${String(reason)}) for ${where}`
          );
        }
        const ok = !allowed
          ? reason === "domain_not_allowed" &&
            connect.mock.calls.length === 0 &&
            harbor.fetch.mock.calls.length === 0
          : matches.length > 1
            ? outcome instanceof ConnectorError &&
              outcome.data.type === "validation_error" &&
              reason === "duplicate_email"
            : JSON.stringify(outcome) ===
              JSON.stringify(
                matches.map(({ user_id, username }) => ({
                  key: String(user_id),
                  value: username,
                }))
              );
        if (!ok) {
          throw new Error(
            `unexpected ${outcome instanceof Error ? outcome.message : JSON.stringify(outcome)} for ${where}`
          );
        }
        vi.unstubAllGlobals();
      }
    }
  );
});

const withProjects = (projects: FakeProject[]): FakeHarborState => ({
  users: [],
  projects,
});

const list = (
  query: ProjectRoleListerQuery,
  connect: ConnectHarbor = connectAs()
) => newProjectRolePrimitives(logger, connect).list(query);

describe("the project lister", () => {
  it("proves the token, then lists every project, by name", async () => {
    const harbor = newFakeHarbor(
      withProjects([
        fakeProject(1, "library", [], true),
        fakeProject(2, "team"),
      ])
    );

    await expect(list({ type: "project", context: INSTANCE })).resolves.toEqual(
      [
        { key: "library", value: "library" },
        { key: "team", value: "team" },
      ]
    );
    expect(harbor.calls()[0]).toBe(
      `GET ${ORIGIN}/api/v2.0/users?page=1&page_size=1`
    );
  });

  // Harbor would answer with the public projects alone.
  it("refuses a credential Harbor doesn't accept, rather than list the public projects", async () => {
    newFakeHarbor(withProjects([fakeProject(1, "library", [], true)]));

    const { data } = await connectorError(() =>
      list({ type: "project", context: INSTANCE }, connectAs(STALE))
    );

    expect(data.payload).toMatchObject({ reason: "admin_token_rejected" });
  });

  // A18: one project, without paging every project.
  it("answers one project with its row when it exists", async () => {
    const harbor = newFakeHarbor(withProjects([fakeProject(2, "team")]));

    await expect(
      list({ type: "project", context: INSTANCE, project: "team" })
    ).resolves.toEqual([{ key: "team", value: "team" }]);
    expect(harbor.calls()).toEqual([
      `HEAD ${ORIGIN}/api/v2.0/projects?project_name=team`,
    ]);
  });

  it("answers one project with nothing when it doesn't exist", async () => {
    newFakeHarbor(withProjects([fakeProject(2, "team")]));

    await expect(
      list({ type: "project", context: INSTANCE, project: "gone" })
    ).resolves.toEqual([]);
  });

  it("refuses a credential Harbor doesn't accept when asked about one project", async () => {
    newFakeHarbor(withProjects([fakeProject(2, "team")]));

    const { data } = await connectorError(() =>
      list(
        { type: "project", context: INSTANCE, project: "team" },
        connectAs(STALE)
      )
    );

    expect(data.payload).toMatchObject({ reason: "admin_token_rejected" });
  });
});

describe("the direct-role lister", () => {
  const directRole = (userId = "42", connect?: ConnectHarbor) =>
    list(
      { type: "direct-role", context: INSTANCE, project: "team", userId },
      connect
    );

  it("returns the role the user holds directly, by name", async () => {
    newFakeHarbor(
      withProjects([fakeProject(2, "team", [memberRow(7, 42, 4)])])
    );

    await expect(directRole()).resolves.toEqual([
      { key: "maintainer", value: "maintainer" },
    ]);
  });

  it("returns nothing when the user holds no direct role", async () => {
    newFakeHarbor(
      withProjects([fakeProject(2, "team", [memberRow(7, 43, 1)])])
    );

    await expect(directRole()).resolves.toEqual([]);
  });

  // P0 manages direct membership only (INT-232).
  it("ignores a group's row, even one whose group id is the user's id", async () => {
    newFakeHarbor(
      withProjects([
        fakeProject(2, "team", [memberRow(7, 42, 1, "g"), memberRow(8, 42, 3)]),
      ])
    );

    await expect(directRole()).resolves.toEqual([
      { key: "guest", value: "guest" },
    ]);
  });

  it("returns nothing when only a group of the same id is a member", async () => {
    newFakeHarbor(
      withProjects([fakeProject(2, "team", [memberRow(7, 42, 1, "g")])])
    );

    await expect(directRole()).resolves.toEqual([]);
  });

  // Page 2 is full and a full page 3 follows, so only stopping on the row
  // leaves page 3 unread.
  it("finds the user's row behind a full page, and stops paging there", async () => {
    const others = (count: number, first: number) =>
      Array.from({ length: count }, (_, i) =>
        memberRow(first + i, first + i + 1000, 2)
      );
    const harbor = newFakeHarbor(
      withProjects([
        fakeProject(2, "team", [
          ...others(100, 100),
          ...others(60, 200),
          memberRow(7, 42, 5),
          ...others(39, 260),
          ...others(100, 300),
        ]),
      ])
    );

    await expect(directRole()).resolves.toEqual([
      { key: "limitedGuest", value: "limitedGuest" },
    ]);
    expect(harbor.fetch).toHaveBeenCalledTimes(2);
  });

  // `[]` would read as "held no direct role", which a grant records as the
  // role to restore.
  it("refuses a project that doesn't exist with project_gone, not an empty list", async () => {
    newFakeHarbor(withProjects([]));

    const { data } = await connectorError(() => directRole());

    expect(data).toEqual({
      type: "validation_error",
      message: `Project team no longer exists on ${HARBOR_HOST}.`,
      payload: { host: HARBOR_HOST, project: "team", reason: "project_gone" },
    });
  });

  it("says the admin account isn't an administrator when Harbor answers 403 on a project that exists", async () => {
    newFakeHarbor(
      notAdmin(withProjects([fakeProject(2, "team", [memberRow(7, 42, 2)])]))
    );

    const { data } = await connectorError(() => directRole());

    expect(data.payload).toMatchObject({ reason: "admin_not_harbor_admin" });
  });

  // Harbor stores any role id a PUT sends.
  // Believed true of Harbor (INT-265's research, read from source, not
  // checked live): its member list leaves such a row out, so the connector
  // can't see it.
  it("returns nothing for a row Harbor's list leaves out, with a role id that isn't one of its five", async () => {
    newFakeHarbor(
      withProjects([fakeProject(2, "team", [memberRow(7, 42, 9)])])
    );

    await expect(directRole()).resolves.toEqual([]);
  });

  // Defence for a Harbor that lists one, such as a later one with a sixth
  // role.
  it("refuses a listed row whose role id isn't one of Harbor's five, rather than read it as no role", async () => {
    newFakeHarbor({
      ...withProjects([fakeProject(2, "team", [memberRow(7, 42, 9)])]),
      listsUnknownRoles: true,
    });

    const { data } = await connectorError(() => directRole());

    expect(data.type).toBe("validation_error");
    expect(data.payload).toEqual({
      host: HARBOR_HOST,
      project: "team",
      userId: "42",
      roleId: 9,
    });
    expect(data.message).toBe(
      `Harbor user 42 holds role id 9 on project team on ${HARBOR_HOST}, which isn't one of Harbor's project roles. Ask a Harbor admin to set the user's role on the project's Members tab.`
    );
  });

  // Rows built around the user: their own row or not, a group row with
  // their id, other users, roles known and unknown, a page of others first.
  const seed = propertySeed();
  it(
    `returns exactly the user's own direct role, never a group's (PROPERTY_SEED=${seed})`,
    { timeout: 30_000 },
    async () => {
      const random = seededRandom(seed);
      const pick = <T>(items: readonly T[]): T => {
        const item = items[Math.floor(random() * items.length)];
        if (item === undefined) throw new Error("picked from no items");
        return item;
      };

      for (let i = 0; i < 300; i++) {
        let id = 1;
        const rows: FakeMember[] = [];
        if (random() < 0.15) {
          for (let n = 0; n < 100; n++) rows.push(memberRow(id++, 1000 + n, 2));
        }
        for (let n = Math.floor(random() * 5); n > 0; n--) {
          rows.push(
            memberRow(
              id++,
              pick([42, 42, 43, 7]),
              pick([1, 2, 3, 4, 5, 5, 0, 6]),
              pick(["u", "g"] as const)
            )
          );
        }
        newFakeHarbor({
          ...withProjects([fakeProject(2, "team", rows)]),
          listsUnknownRoles: true,
        });

        const own = rows.find(
          (member) => member.entity_type === "u" && member.entity_id === 42
        );
        const ownRole = own === undefined ? undefined : roleOf(own.role_id);
        const expected =
          own === undefined
            ? { rows: [] }
            : ownRole === undefined
              ? { error: own.role_id }
              : { rows: [{ key: ownRole, value: ownRole }] };

        const got = await directRole().then(
          (rows) => ({ rows }),
          (error: unknown) => ({
            error:
              error instanceof ConnectorError
                ? error.data.payload.roleId
                : String(error),
          })
        );

        if (JSON.stringify(got) !== JSON.stringify(expected)) {
          throw new Error(
            `expected ${JSON.stringify(expected)}, got ${JSON.stringify(got)} for ${JSON.stringify(rows.slice(-5))}`
          );
        }
        vi.unstubAllGlobals();
      }
    }
  );
});

// P0 never gets here, since getUser always answers, and the connector never
// creates Harbor users.
describe("createUser", () => {
  it("refuses, and calls nothing", async () => {
    const harbor = newFakeHarbor(state([]));

    const { data } = await connectorError(() =>
      newProjectRolePrimitives(logger, connectAs()).createUser(
        {
          ...INSTANCE,
          requestId: "req-1",
          email: "a@example.com",
          priorRole: null,
        },
        { instanceId: "p0-harbor", userId: "42" }
      )
    );

    expect(data).toEqual({
      type: "unknown",
      message:
        "P0 asked the Harbor connector to create a Harbor user, which it never does.",
      payload: { requestId: "req-1" },
    });
    expect(harbor.fetch).not.toHaveBeenCalled();
  });
});

// The router builds the primitives with the request's logger and the real
// connect, which reads the secret.
describe("the member lister, through the router", () => {
  it("reads the instance's secret, and answers with the user", async () => {
    vi.mocked(readAdminCredential).mockResolvedValue(ADMIN_CREDENTIAL);
    withProvider(newFakeHarbor(state([user(3, "alice@example.com")])));

    await expect(
      connectorRouter
        .createCaller({ logger })
        .harbor.accesses.projectRole.list({
          query: {
            type: "member",
            context: INSTANCE,
            email: "alice@example.com",
          },
        })
    ).resolves.toEqual([{ key: "3", value: "user3" }]);
    expect(readAdminCredential).toHaveBeenCalledWith(
      INSTANCE.secret,
      expect.anything()
    );
  });

  it("refuses an email outside the allowed domains before it reads the secret or calls Harbor", async () => {
    vi.mocked(readAdminCredential).mockResolvedValue(ADMIN_CREDENTIAL);
    const harbor = newFakeHarbor(state([user(3, "alice@other.com")]));

    await expect(
      connectorRouter
        .createCaller({ logger })
        .harbor.accesses.projectRole.list({
          query: {
            type: "member",
            context: INSTANCE,
            email: "alice@other.com",
          },
        })
    ).rejects.toMatchObject({
      data: {
        type: "validation_error",
        payload: { reason: "domain_not_allowed" },
      },
    });
    expect(readAdminCredential).not.toHaveBeenCalled();
    expect(harbor.fetch).not.toHaveBeenCalled();
  });
});
