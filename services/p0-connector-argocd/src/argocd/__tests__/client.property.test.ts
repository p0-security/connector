/**
 * Property tests for the client's parsers of Argo CD's answers: userinfo,
 * can-i, the projects list and `argocd-rbac-cm`'s manifest string. (The
 * version string's are in version.test.ts.) Each answer is a valid one with
 * random damage done to it, and each has an oracle written as plain checks,
 * apart from the client's schemas. Whatever the answer, the client returns
 * what the oracle says or fails with the oracle's ArgoCdError, and logs none
 * of the answer's values.
 *
 * Modelled on src/__tests__/instance.property.test.ts. A failure names the
 * seed and the answer: `PROPERTY_SEED=<n>` replays it.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  TOKEN,
  logger,
  propertySeed,
  recordLogger,
  seededRandom,
} from "../../__tests__/fixtures.ts";
import { ArgoCdError, type ArgoCdFailure } from "../api.ts";
import { argoCdClientFor } from "../client.ts";
import { ARGOCD_ORIGIN } from "./fake-argocd.ts";

const seed = propertySeed();
// Thousands of cases, which a loaded machine can take seconds over.
const OPTIONS = { timeout: 60_000 };
const CASES = 1500;

// Marks every value of an answer, so a log line that repeats one shows.
const MARK = "ZQJX";

const client = () =>
  argoCdClientFor({ url: ARGOCD_ORIGIN, token: TOKEN, logger });

type Expected = { failure: ArgoCdFailure } | { ok: unknown };
const WRONG_SHAPE: Expected = {
  failure: { kind: "unexpected", reason: "wrong_shape" },
};

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isString = (value: unknown, min: number, max: number) =>
  typeof value === "string" && value.length >= min && value.length <= max;
const isName = (value: unknown) => isString(value, 1, 253);
/** Absent or null, which the gateway sends for an empty list. */
const isNone = (value: unknown) => value === undefined || value === null;

/** The generators every test shares, on one seeded source. */
const generators = () => {
  const random = seededRandom(seed);
  const int = (below: number) => Math.floor(random() * below);
  const pick = <T>(items: readonly T[]): T => {
    const item = items[int(items.length)];
    if (item === undefined) throw new Error("picked from no items");
    return item;
  };
  /** A string that is mostly a name, sometimes not one. */
  const str = () =>
    pick([
      () => `${MARK}-${int(100)}`,
      () => `${MARK}-${int(100)}`,
      () => `${MARK}-${int(100)}`,
      () => "",
      () => `${MARK}${"a".repeat(pick([248, 249, 250, 1020, 1021]))}`,
    ])();
  /** Anything JSON holds, for a field that should be something else. */
  const junk = (): unknown =>
    pick([
      () => null,
      () => int(10),
      () => random() < 0.5,
      () => str(),
      () => [str()],
      () => ({ [MARK]: str() }),
    ])();
  /**
   * `valid`, mostly, or damaged: a field dropped, replaced with junk, or a
   * new one added.
   */
  const damage = <T extends Record<string, unknown>>(valid: T): unknown => {
    const roll = random();
    if (roll < 0.6) return valid;
    const keys = Object.keys(valid);
    const key = keys.length > 0 ? pick(keys) : "x";
    if (roll < 0.75) {
      const { [key]: _dropped, ...rest } = valid;
      return rest;
    }
    if (roll < 0.95) return { ...valid, [key]: junk() };
    return { ...valid, [`${MARK}extra`]: junk() };
  };
  /** An array of `make()`, or something that isn't a list. */
  const listOf = (make: () => unknown): unknown =>
    pick([
      () => Array.from({ length: int(4) }, make),
      () => Array.from({ length: int(4) }, make),
      () => Array.from({ length: int(4) }, make),
      () => null,
      () => undefined,
      () => junk(),
    ])();
  return { random, int, pick, str, junk, damage, listOf };
};

/** What the client gave for `answer`: its value, or its failure. */
const outcomeOf = async (
  answer: unknown,
  run: () => Promise<unknown>
): Promise<Expected> => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify(answer)))
  );
  try {
    return { ok: await run() };
  } catch (error) {
    if (error instanceof ArgoCdError) return { failure: error.failure };
    throw error;
  }
};

/** Fails the test with the seed and the case. */
const check = (actual: Expected, expected: Expected, answer: unknown) => {
  try {
    expect(actual).toEqual(expected);
  } catch (error) {
    throw new Error(
      `PROPERTY_SEED=${seed}, for ${JSON.stringify(answer)?.slice(0, 400)}: ${String(error)}`,
      { cause: error }
    );
  }
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe(`the client's parsers, over random answers (PROPERTY_SEED=${seed})`, () => {
  it(
    "userInfo is the account when logged in, anonymous when not or when loggedIn is left out, and wrong_shape otherwise",
    OPTIONS,
    async () => {
      const { pick, str, damage, junk } = generators();
      const log = recordLogger();
      for (let i = 0; i < CASES; i++) {
        const answer = pick([
          () =>
            damage({
              loggedIn: true,
              username: str(),
              iss: pick(["argocd", str()]),
            }),
          () => damage({ loggedIn: false }),
          () =>
            damage({
              loggedIn: pick([true, false]),
              username: str(),
              iss: str(),
              groups: [str()],
            }),
          () => junk(),
        ])();

        const expected: Expected = !isObject(answer)
          ? WRONG_SHAPE
          : // Go leaves out an `omitempty` false, so absent is false.
            answer.loggedIn === false || answer.loggedIn === undefined
            ? { failure: { kind: "anonymous" } }
            : answer.loggedIn === true &&
                isName(answer.username) &&
                (answer.iss === undefined || isString(answer.iss, 0, 1024))
              ? {
                  ok: { username: answer.username, issuer: answer.iss ?? "" },
                }
              : WRONG_SHAPE;

        check(
          await outcomeOf(answer, () => client().userInfo()),
          expected,
          answer
        );
      }
      expect(log.seen()).not.toContain(MARK);
    }
  );

  it(
    "canI is yes or no, and wrong_shape for anything else",
    OPTIONS,
    async () => {
      const { pick, damage, junk } = generators();
      const log = recordLogger();
      for (let i = 0; i < CASES; i++) {
        const answer = pick([
          () => damage({ value: pick(["yes", "no"]) }),
          () => ({ value: pick(["Yes", "NO", "true", "", ` yes`, MARK]) }),
          () => junk(),
        ])();

        const value = isObject(answer) ? answer.value : undefined;
        const expected: Expected =
          value === "yes"
            ? { ok: true }
            : value === "no"
              ? { ok: false }
              : WRONG_SHAPE;

        check(
          await outcomeOf(answer, () =>
            client().canI("applications", "sync", "*/*")
          ),
          expected,
          answer
        );
      }
      expect(log.seen()).not.toContain(MARK);
    }
  );

  it(
    "listProjects is each project's name and roles, null lists empty, and wrong_shape otherwise",
    OPTIONS,
    async () => {
      const { pick, str, damage, listOf, junk } = generators();
      const log = recordLogger();
      const role = () =>
        damage({
          name: str(),
          groups: listOf(() => pick([str(), str(), junk()])),
        });
      const project = () =>
        damage({
          metadata: damage({ name: str(), namespace: "argocd" }),
          spec: damage({ roles: listOf(role), sourceRepos: ["*"] }),
        });
      for (let i = 0; i < CASES; i++) {
        const answer = pick([
          () => damage({ metadata: {}, items: listOf(project) }),
          () => junk(),
        ])();

        // The oracle: a list is an array or nothing; every name is a name.
        const rolesOf = (roles: unknown) => {
          if (isNone(roles)) return [];
          if (!Array.isArray(roles)) return undefined;
          const out = [];
          for (const r of roles) {
            if (!isObject(r) || !isName(r.name)) return undefined;
            const groups = isNone(r.groups) ? [] : r.groups;
            if (
              !Array.isArray(groups) ||
              !groups.every((g) => isString(g, 0, 1024))
            ) {
              return undefined;
            }
            out.push({ name: r.name, groups });
          }
          return out;
        };
        const projectsOf = (items: unknown) => {
          if (isNone(items)) return [];
          if (!Array.isArray(items)) return undefined;
          const out = [];
          for (const p of items) {
            if (
              !isObject(p) ||
              !isObject(p.metadata) ||
              !isName(p.metadata.name)
            ) {
              return undefined;
            }
            if (!isObject(p.spec)) return undefined;
            const roles = rolesOf(p.spec.roles);
            if (!roles) return undefined;
            out.push({ name: p.metadata.name, roles });
          }
          return out;
        };
        const projects = isObject(answer)
          ? projectsOf(answer.items)
          : undefined;
        const expected: Expected = projects ? { ok: projects } : WRONG_SHAPE;

        check(
          await outcomeOf(answer, () => client().listProjects()),
          expected,
          answer
        );
      }
      expect(log.seen()).not.toContain(MARK);
    }
  );

  it(
    "readRbacConfigMap is the ConfigMap's data, from a manifest string, or not_json or wrong_shape",
    OPTIONS,
    async () => {
      const { pick, str, damage, junk, int } = generators();
      const log = recordLogger();
      const NAMESPACE = "argocd";
      for (let i = 0; i < CASES; i++) {
        const data = pick([
          () =>
            Object.fromEntries(
              Array.from({ length: int(4) }, () => [
                `policy.${int(9)}.csv`,
                str(),
              ])
            ),
          () =>
            Object.fromEntries(
              Array.from({ length: int(4) }, () => [
                `policy.${int(9)}.csv`,
                str(),
              ])
            ),
          () => null,
          () => undefined,
          () => ({ "policy.csv": junk() }),
          () => [str()],
          () => junk(),
        ])();
        const object = damage({
          apiVersion: pick(["v1", "v1", "v1", "v2", "apps/v1"]),
          kind: pick(["ConfigMap", "ConfigMap", "ConfigMap", "Secret"]),
          metadata: damage({
            name: pick([
              "argocd-rbac-cm",
              "argocd-rbac-cm",
              "argocd-rbac-cm",
              "argocd-cm",
            ]),
            namespace: pick([NAMESPACE, NAMESPACE, NAMESPACE, "other", ""]),
            resourceVersion: "1",
          }),
          data,
        });
        const text = JSON.stringify(object) ?? "";
        const manifest = pick([
          () => text,
          () => text,
          () => text,
          () => text.slice(0, int(text.length)),
          () => `${MARK}<html>`,
        ])();
        const answer = pick([
          () => ({ manifest }),
          () => ({ manifest }),
          () => damage({ manifest }),
        ])();

        const oracle = (): Expected => {
          if (!isObject(answer) || typeof answer.manifest !== "string")
            return WRONG_SHAPE;
          let parsed: unknown;
          try {
            parsed = JSON.parse(answer.manifest);
          } catch {
            return { failure: { kind: "unexpected", reason: "not_json" } };
          }
          if (
            !isObject(parsed) ||
            parsed.apiVersion !== "v1" ||
            parsed.kind !== "ConfigMap" ||
            !isObject(parsed.metadata) ||
            parsed.metadata.name !== "argocd-rbac-cm" ||
            parsed.metadata.namespace !== NAMESPACE
          ) {
            return WRONG_SHAPE;
          }
          if (isNone(parsed.data)) return { ok: { data: {} } };
          if (
            !isObject(parsed.data) ||
            !Object.values(parsed.data).every((v) => typeof v === "string")
          ) {
            return WRONG_SHAPE;
          }
          return { ok: { data: parsed.data } };
        };

        check(
          await outcomeOf(answer, () =>
            client().readRbacConfigMap({ app: "argocd", namespace: NAMESPACE })
          ),
          oracle(),
          answer
        );
      }
      expect(log.seen()).not.toContain(MARK);
    }
  );

  it("names the seed it ran with", () => {
    expect(Number.isSafeInteger(seed)).toBe(true);
  });
});
