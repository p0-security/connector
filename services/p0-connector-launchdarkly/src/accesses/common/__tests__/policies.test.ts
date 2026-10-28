import { describe, expect, it, vi } from "vitest";

import {
  ACCOUNT,
  API,
  EMAIL,
  LAUNCHDARKLY_HOST,
  MEMBER_ID,
  NEVER_SHOWN,
  OTHER_ACCOUNT_ID,
  USER_BODY,
  baseContext,
  connectorError,
  logger,
  memberOf,
  noPause,
  recordLogger,
  stubPatternAndToken,
} from "../../../__tests__/fixtures.ts";
import { DOMAIN_ALLOW_PATTERN_ENV } from "../../../allowlist.ts";
import {
  type FakeLaunchDarklyState,
  type FakeMember,
  PERSONAL_CALLER,
  fakeMember,
  newFakeLaunchDarkly,
} from "../../../launchdarkly/__tests__/fake-launchdarkly.ts";
import { readToken } from "../../../secrets.ts";
import { baseRole } from "../../base-role/definition.ts";
import { newBaseRolePrimitives } from "../../base-role/handler.ts";
import type { BaseRequestContext } from "../definition.ts";
import {
  ACCESSES,
  type Access,
  type Pause,
  READ_BACK_MAX_PAUSE_MS,
  READ_BACK_PAUSE_MS,
  READ_BACK_READS,
} from "../policies.ts";

// The secret manager is `secrets.test.ts`'s business. Here the read answers
// with the token.
vi.mock("../../../secrets.ts");

/** The writes the connector may make for the member, and nothing else. */
const ALLOWED_WRITES = [`PATCH ${API}/members/${MEMBER_ID}`];

/** The member's own route, as every read of them asks for it. */
const MEMBER_READ = `GET ${API}/members/${MEMBER_ID}`;

/** One access, as the tests below drive it. */
type Case = {
  /** The member holding what the request grants, besides who they are. */
  granted: Partial<FakeMember>;
  holds: (member: FakeMember) => boolean;
  /** The policies when the request's own target is held, and nothing else. */
  held: string[];
  run: (
    context: BaseRequestContext,
    policies: string[],
    pause: Pause
  ) => Promise<void>;
};

const CASES: Record<Access, Case> = {
  "base-role": {
    granted: { role: "writer" },
    holds: ({ role }) => role === "writer",
    held: ["writer"],
    run: (context, policies, pause) =>
      newBaseRolePrimitives(logger, pause).setPoliciesForUser(
        { ...context, role: "writer", priorRole: "reader" },
        MEMBER_ID,
        USER_BODY,
        baseRole.array().parse(policies)
      ),
  },
};

/** A LaunchDarkly where the member holds the access when `granted`. */
const launchDarklyWith = (
  access: Access,
  options: FakeLaunchDarklyState & {
    granted?: boolean;
    member?: Partial<FakeMember>;
  } = {}
) => {
  const { granted = false, member = {}, ...state } = options;
  return newFakeLaunchDarkly({
    members: [
      fakeMember({
        _id: MEMBER_ID,
        email: EMAIL,
        ...(granted ? CASES[access].granted : {}),
        ...member,
      }),
    ],
    ...state,
  });
};

type LaunchDarkly = ReturnType<typeof launchDarklyWith>;

/** Runs the access: a grant with its own target held, unless told otherwise. */
const run = (
  access: Access,
  options: Partial<BaseRequestContext> & {
    policies?: string[];
    pause?: Pause;
  } = {}
) => {
  const {
    policies = CASES[access].held,
    pause = noPause,
    ...context
  } = options;
  return CASES[access].run(baseContext(context), policies, pause);
};

stubPatternAndToken();

describe.each(ACCESSES)("%s", (access) => {
  const { holds } = CASES[access];

  describe("the user primitives", () => {
    const primitives = () =>
      ({ "base-role": newBaseRolePrimitives })[access](logger);

    it("answers the body's member id, without calling LaunchDarkly", async () => {
      const launchDarkly = launchDarklyWith(access);

      await expect(
        // @ts-expect-error -- the user primitives read the base context only.
        primitives().getUser(baseContext(), {
          memberId: MEMBER_ID,
          accountId: ACCOUNT.accountId,
        })
      ).resolves.toBe(MEMBER_ID);
      expect(readToken).not.toHaveBeenCalled();
      expect(launchDarkly.calls()).toEqual([]);
    });

    it("never invites a member, and deletes none", async () => {
      const launchDarkly = launchDarklyWith(access);
      const body = { memberId: MEMBER_ID, accountId: ACCOUNT.accountId };

      const { data } = await connectorError(() =>
        // @ts-expect-error -- the user primitives read the base context only.
        primitives().createUser(baseContext(), body)
      );
      // @ts-expect-error -- the user primitives read the base context only.
      await primitives().deleteUser(baseContext(), MEMBER_ID, USER_BODY);

      expect(data.type).toBe("unknown");
      expect(launchDarkly.calls()).toEqual([]);
    });
  });

  describe("a grant", () => {
    it("gives the access, writing only the allowlisted routes, as JSON with no comment", async () => {
      const launchDarkly = launchDarklyWith(access);

      await run(access);

      expect(holds(memberOf(launchDarkly))).toBe(true);
      const writes = launchDarkly.writes();
      expect(writes.length).toBeGreaterThan(0);
      for (const { call, contentType, body } of writes) {
        expect(ALLOWED_WRITES).toContain(call);
        expect(contentType).toBe("application/json");
        expect(JSON.stringify(body)).not.toContain("P0 request");
      }
    });

    it("checks the domain, the caller and the member, in that order, before it writes", async () => {
      const launchDarkly = launchDarklyWith(access);

      await run(access);

      const calls = launchDarkly.calls();
      const firstWrite = calls.findIndex((call) => !call.startsWith("GET "));
      expect(calls.slice(0, 2)).toEqual([
        `GET ${API}/caller-identity`,
        MEMBER_READ,
      ]);
      expect(firstWrite).toBeGreaterThanOrEqual(2);
    });

    it("is safe to run twice: the second writes nothing", async () => {
      const launchDarkly = launchDarklyWith(access);
      await run(access);
      const before = launchDarkly.writes().length;

      await run(access);

      expect(holds(memberOf(launchDarkly))).toBe(true);
      expect(launchDarkly.writes()).toHaveLength(before);
    });

    it("refuses an email outside the allowed domains, before it reads the secret", async () => {
      const launchDarkly = launchDarklyWith(access);

      const { data } = await connectorError(() =>
        run(access, { email: "sentinel-person@elsewhere.com" })
      );

      expect(data.payload).toEqual({ reason: "domain_not_allowed" });
      expect(readToken).not.toHaveBeenCalled();
      expect(launchDarkly.calls()).toEqual([]);
    });

    it("refuses every email while the pattern is unset", async () => {
      vi.stubEnv(DOMAIN_ALLOW_PATTERN_ENV, undefined);
      const launchDarkly = launchDarklyWith(access);

      const { data } = await connectorError(() => run(access));

      expect(data.payload).toEqual({ reason: "domain_pattern_unusable" });
      expect(launchDarkly.calls()).toEqual([]);
    });

    it("refuses the member the access token acts as (own_member)", async () => {
      const launchDarkly = launchDarklyWith(access, {
        caller: { ...PERSONAL_CALLER, memberId: MEMBER_ID },
      });

      const { data } = await connectorError(() => run(access));

      expect(data).toMatchObject({
        type: "validation_error",
        payload: {
          host: LAUNCHDARKLY_HOST,
          memberId: MEMBER_ID,
          reason: "own_member",
        },
      });
      expect(launchDarkly.writes()).toEqual([]);
      expect(holds(memberOf(launchDarkly))).toBe(false);
    });

    it.each<[changed: string, state: Parameters<typeof launchDarklyWith>[1]]>([
      ["account", { accountId: OTHER_ACCOUNT_ID }],
      ["deleted", { members: [] }],
      ["email", { member: { email: "someone-else@example.com" } }],
      ["pending_invite", { member: { _pendingInvite: true } }],
      ["unverified", { member: { _verified: false } }],
    ])(
      "refuses when the member changed since P0 found them (%s)",
      async (changed, state) => {
        const launchDarkly = launchDarklyWith(access, state);

        const { data } = await connectorError(() => run(access));

        expect(data).toMatchObject({
          type: "validation_error",
          payload: {
            host: LAUNCHDARKLY_HOST,
            memberId: MEMBER_ID,
            changed,
            reason: "member_changed",
          },
        });
        expect(launchDarkly.writes()).toEqual([]);
      }
    );

    it("matches the email ignoring ASCII case", async () => {
      const launchDarkly = launchDarklyWith(access);

      await run(access, { email: "Sentinel-Person@Example.COM" });

      expect(holds(memberOf(launchDarkly))).toBe(true);
    });

    describe("reads the member back", () => {
      /** Answers every write with success, without making it. */
      const ignoreWrites = (launchDarkly: LaunchDarkly) =>
        launchDarkly.intercept(({ method }) =>
          method === "GET" ? undefined : Response.json({})
        );

      it(`fails when the change doesn't show after ${READ_BACK_READS} reads, a second apart`, async () => {
        const launchDarkly = launchDarklyWith(access);
        ignoreWrites(launchDarkly);
        const pause = vi.fn<Pause>(async () => {});

        const { data } = await connectorError(() => run(access, { pause }));

        expect(data).toMatchObject({
          type: "dependency_violation",
          payload: { host: LAUNCHDARKLY_HOST, memberId: MEMBER_ID },
        });
        expect(data.message).toContain(
          "but reading the member back 3 times didn't show it, so P0 takes the change back."
        );
        expect(pause.mock.calls).toEqual([
          [READ_BACK_PAUSE_MS],
          [READ_BACK_PAUSE_MS],
        ]);
        const reads = launchDarkly
          .calls()
          .filter((call) => call === MEMBER_READ);
        // The grant's own read, then the three reads back.
        expect(reads).toHaveLength(1 + READ_BACK_READS);
      });

      it("succeeds when the change shows on a later read", async () => {
        const launchDarkly = launchDarklyWith(access);
        ignoreWrites(launchDarkly);
        // LaunchDarkly makes the change while the connector waits.
        const pause = vi.fn<Pause>(async () => {
          Object.assign(memberOf(launchDarkly), CASES[access].granted);
        });

        await run(access, { pause });

        expect(pause).toHaveBeenCalledTimes(1);
      });

      it("reads again when LaunchDarkly limits the first read back", async () => {
        const launchDarkly = launchDarklyWith(access);
        let reads = 0;
        launchDarkly.intercept(({ method, url }) => {
          if (`${method} ${url}` !== MEMBER_READ) return undefined;
          reads++;
          // The grant's own read, then the first read back.
          return reads === 2
            ? Response.json(
                { code: "rate_limited", message: "slow down" },
                { status: 429, headers: { "Retry-After": "5" } }
              )
            : undefined;
        });
        const pause = vi.fn<Pause>(async () => {});

        await run(access, { pause });

        expect(holds(memberOf(launchDarkly))).toBe(true);
        expect(pause.mock.calls).toEqual([[READ_BACK_MAX_PAUSE_MS]]);
      });
    });
  });

  describe("a revoke", () => {
    it("takes the access back", async () => {
      const launchDarkly = launchDarklyWith(access, { granted: true });

      await run(access, { operation: "revoke", policies: [] });

      expect(holds(memberOf(launchDarkly))).toBe(false);
      for (const { call } of launchDarkly.writes()) {
        expect(ALLOWED_WRITES).toContain(call);
      }
    });

    // Taking access away never depends on the allowlist, on the member still
    // being the one P0 found, or on whose token it is within the account.
    it("checks neither the domain, the token's own member nor the member's email", async () => {
      vi.stubEnv(DOMAIN_ALLOW_PATTERN_ENV, undefined);
      const launchDarkly = launchDarklyWith(access, {
        granted: true,
        member: { email: "someone-else@elsewhere.com", _verified: false },
        caller: { ...PERSONAL_CALLER, memberId: MEMBER_ID },
      });

      await run(access, {
        operation: "revoke",
        policies: [],
        email: "sentinel-person@elsewhere.com",
      });

      expect(holds(memberOf(launchDarkly))).toBe(false);
    });

    // With another account's token, the member id would find no one, and
    // the revoke would read as done with the access still in place.
    it("fails, writing nothing, when the token belongs to another account", async () => {
      const log = recordLogger();
      const launchDarkly = launchDarklyWith(access, {
        granted: true,
        accountId: OTHER_ACCOUNT_ID,
      });

      const { data } = await connectorError(() =>
        run(access, { operation: "revoke", policies: [] })
      );

      expect(data).toMatchObject({
        type: "insufficient_privileges",
        payload: { host: LAUNCHDARKLY_HOST, memberId: MEMBER_ID },
      });
      expect(data.payload).not.toHaveProperty("reason");
      expect(data.message).toContain("belongs to another account");
      expect(launchDarkly.calls()).toEqual([`GET ${API}/caller-identity`]);
      expect(holds(memberOf(launchDarkly))).toBe(true);
      const seen = log.seen(data);
      for (const marker of NEVER_SHOWN) expect(seen).not.toContain(marker);
    });

    it("checks the token's account before anything else", async () => {
      const launchDarkly = launchDarklyWith(access, { granted: true });

      await run(access, { operation: "revoke", policies: [] });

      expect(launchDarkly.calls()[0]).toBe(`GET ${API}/caller-identity`);
    });

    it("is safe to run twice", async () => {
      const launchDarkly = launchDarklyWith(access, { granted: true });
      await run(access, { operation: "revoke", policies: [] });
      const before = structuredClone(memberOf(launchDarkly));

      await run(access, { operation: "revoke", policies: [] });

      expect(memberOf(launchDarkly)).toEqual(before);
    });

    it("is done when LaunchDarkly no longer has the member", async () => {
      const launchDarkly = launchDarklyWith(access, { members: [] });

      await expect(
        run(access, { operation: "revoke", policies: [] })
      ).resolves.toBeUndefined();
      expect(launchDarkly.state.members).toEqual([]);
    });

    it("leaves a target a sibling request still holds, and warns", async () => {
      const log = recordLogger();
      const launchDarkly = launchDarklyWith(access, { granted: true });

      await run(access, { operation: "revoke" });

      expect(holds(memberOf(launchDarkly))).toBe(true);
      expect(launchDarkly.writes()).toEqual([]);
      expect(log.lines()).toContainEqual([
        "the call says revoke, but a sibling request still holds the request's own target, which the revoke leaves in place",
      ]);
    });
  });

  // P0 sets `operation` from the request's status, so the rollback of a
  // failed grant still says `grant`.
  describe("a call that says grant but doesn't hold the request's own target", () => {
    it("is a revoke: it takes the access back, without the grant's checks, and warns", async () => {
      vi.stubEnv(DOMAIN_ALLOW_PATTERN_ENV, undefined);
      const log = recordLogger();
      const launchDarkly = launchDarklyWith(access, {
        granted: true,
        member: { email: "someone-else@elsewhere.com" },
      });

      await run(access, { operation: "grant", policies: [] });

      expect(holds(memberOf(launchDarkly))).toBe(false);
      expect(log.lines()).toContainEqual([
        "the call says grant, but the request's own target isn't in its policies, so it is treated as the rollback of a failed grant",
      ]);
    });

    it("takes back a grant that failed after its write", async () => {
      const launchDarkly = launchDarklyWith(access);
      await run(access);

      await run(access, { operation: "grant", policies: [] });

      expect(holds(memberOf(launchDarkly))).toBe(false);
    });
  });

  describe("what it logs and throws", () => {
    const RUNS: [what: string, run: () => Promise<unknown>][] = [
      ["a grant", () => run(access)],
      ["a revoke", () => run(access, { operation: "revoke", policies: [] })],
      [
        "a refusal",
        () => run(access, { email: "sentinel-person@elsewhere.com" }),
      ],
    ];

    it.each(RUNS)(
      "carries no token, secret or email, on %s",
      async (_case, go) => {
        const log = recordLogger();
        launchDarklyWith(access, { member: { email: EMAIL } });

        const outcome = await go().catch((error: unknown) => error);

        const seen = log.seen(outcome);
        for (const marker of NEVER_SHOWN) expect(seen).not.toContain(marker);
        expect(seen).not.toContain("sentinel-person@");
      }
    );
  });
});
