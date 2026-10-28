import { ConnectorError } from "@p0security/connector";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ALLOWED_EMAIL_DOMAIN_PATTERN_ENV,
  assertAllowedEmail,
  compileAllowlist,
} from "../allowlist.ts";
import {
  connectorError,
  logger,
  propertySeed,
  recordLogger,
  seededRandom,
} from "./fixtures.ts";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

const withPattern = (pattern: string | undefined) =>
  vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, pattern);

const check = (email: string) => assertAllowedEmail(email, logger);

/** The `ConnectorError` `assertAllowedEmail` refuses `email` with. */
const refusal = (email: string) => connectorError(async () => check(email));

// The engine's own words for the two broken patterns below.
const UNMATCHED_PAREN = (pattern: string) =>
  `Invalid regular expression: /${pattern}/: Unmatched ')'`;
const UNTERMINATED_GROUP = (pattern: string) =>
  `Invalid regular expression: /${pattern}/: Unterminated group`;

describe("compileAllowlist", () => {
  it("reads ALLOWED_EMAIL_DOMAIN_PATTERN, and keeps it trimmed", () => {
    withPattern(" p0\\.dev|p0security\\.com\n");
    // Anchored, case-insensitive, and with no `g` flag, which would make
    // `test` start each call where the last one stopped.
    expect(compileAllowlist()).toEqual({
      ok: true,
      pattern: "p0\\.dev|p0security\\.com",
      regex: /^(?:p0\.dev|p0security\.com)$/i,
    });
  });

  it.each([
    ["unset", undefined, { reason: "unset" }],
    ["empty", "", { reason: "unset" }],
    ["blank", " \t\n", { reason: "unset" }],
    [
      "not a regex",
      "p0\\.(dev",
      { reason: "invalid_regex", detail: UNTERMINATED_GROUP("p0\\.(dev") },
    ],
    // Wrapped, this one compiles, to `^(?:p0\.dev)|(evil\.com)$`, which
    // allows any domain that starts with `evil.com`.
    [
      "a regex only once it is wrapped",
      "p0\\.dev)|(evil\\.com",
      {
        reason: "invalid_regex",
        detail: UNMATCHED_PAREN("p0\\.dev)|(evil\\.com"),
      },
    ],
  ])(
    "says why there is no allowlist when the pattern is %s",
    (_case, pattern, problem) => {
      withPattern(pattern);
      expect(compileAllowlist()).toEqual({ ok: false, problem });
    }
  );
});

describe("assertAllowedEmail", () => {
  it.each([
    ["an allowed domain", "alice@p0.dev"],
    ["the other side of an alternation", "alice@p0security.com"],
    ["an allowed domain in another case", "Alice@P0.Dev"],
  ])("lets %s through", (_case, email) => {
    withPattern("p0\\.dev|p0security\\.com");
    expect(() => check(email)).not.toThrow();
  });

  it.each([
    ["another domain", "mallory@evil.io"],
    ["a domain that ends with an allowed one", "mallory@evil-p0.dev"],
    ["a domain that starts with an allowed one", "mallory@p0.dev.evil.io"],
    ["a subdomain the pattern doesn't name", "alice@eng.p0.dev"],
    ["an allowed domain in the local part", "p0.dev@evil.io"],
    ["an address with no @", "alice"],
    ["an address with nothing after the @", "alice@"],
    ["an address with nothing before the @", "@p0.dev"],
    ["an address with two @s", "mallory@evil.io@p0.dev"],
    ["a quoted local part with an @ in it", '"a@b"@p0.dev'],
    ["an allowed domain with a trailing space", "alice@p0.dev "],
  ])("refuses %s with INT-231's message", async (_case, email) => {
    withPattern("p0\\.dev|p0security\\.com");

    const { data } = await refusal(email);

    expect(data).toEqual({
      type: "validation_error",
      message: `${email} isn't in an email domain this Harbor connector allows.`,
      payload: { reason: "domain_not_allowed" },
    });
  });

  it("follows the pattern's own rule for subdomains", () => {
    withPattern("([a-z0-9-]+\\.)*p0\\.dev");
    expect(() => check("alice@eng.p0.dev")).not.toThrow();
    expect(() => check("alice@p0.dev")).not.toThrow();
  });

  // Anchors are the connector's job, and harmless when the pattern has them.
  it("takes a pattern that anchors itself", () => {
    withPattern("^p0\\.dev$");
    expect(() => check("alice@p0.dev")).not.toThrow();
  });

  it("refuses everything a pattern that only compiles once wrapped would let through", async () => {
    withPattern("p0\\.dev)|(evil\\.com");
    await expect(
      refusal("mallory@evil.com.attacker.io")
    ).resolves.toMatchObject({
      data: { payload: { reason: "domain_pattern_unusable" } },
    });
  });

  // Nothing is allowed until the connector has a pattern that compiles. The
  // connector's setup is at fault, so the email isn't repeated.
  it.each([
    ["unset", undefined, "ALLOWED_EMAIL_DOMAIN_PATTERN isn't set"],
    ["empty", "", "ALLOWED_EMAIL_DOMAIN_PATTERN isn't set"],
    ["blank", " \t", "ALLOWED_EMAIL_DOMAIN_PATTERN isn't set"],
    [
      "not a regex that compiles",
      "p0\\.(dev",
      "ALLOWED_EMAIL_DOMAIN_PATTERN isn't a regular expression that compiles (the connector's log says why)",
    ],
  ])(
    "refuses every email when the pattern is %s, and logs why without the email",
    async (_case, pattern, problem) => {
      const log = recordLogger();
      withPattern(pattern);

      const { data } = await refusal("alice@p0.dev");

      expect(data).toEqual({
        type: "validation_error",
        message: `The Harbor connector refuses every request: ${problem}. Set it on the connector to a regular expression for the email domains that may receive access.`,
        payload: { reason: "domain_pattern_unusable" },
      });
      expect(log.lines()).toEqual([
        [
          { problem: expect.objectContaining({ reason: expect.any(String) }) },
          "the email domain allowlist is unusable; refusing every email",
        ],
      ]);
      expect(log.seen(data)).not.toContain("alice");
    }
  );

  // A message reaches requesters. The pattern is the customer's setup, and
  // the regex engine's message quotes it, so only the log has them.
  it("names neither the pattern nor the regex engine's error, and logs the engine's error", async () => {
    const log = recordLogger();
    withPattern("p0\\.(dev");

    const { data } = await refusal("alice@p0.dev");

    expect(data.message).not.toContain("p0\\.(dev");
    expect(data.message).not.toContain("Unterminated group");
    expect(log.lines()).toEqual([
      [
        {
          problem: {
            reason: "invalid_regex",
            detail: UNTERMINATED_GROUP("p0\\.(dev"),
          },
        },
        expect.any(String),
      ],
    ]);
  });

  it("logs nothing when the email is allowed or refused for its domain", async () => {
    const log = recordLogger();
    withPattern("p0\\.dev");
    check("alice@p0.dev");
    await refusal("mallory@evil.io");
    expect(log.lines()).toHaveLength(0);
  });

  // The pattern is read on every call, so a narrowed pattern takes effect on
  // the next request, not the next cold start.
  it("follows a change to the pattern", async () => {
    withPattern("p0\\.dev");
    expect(() => check("alice@p0.dev")).not.toThrow();

    withPattern("p0security\\.com");
    await expect(refusal("alice@p0.dev")).resolves.toMatchObject({
      data: { payload: { reason: "domain_not_allowed" } },
    });
  });
});

// Emails built from the characters the rule turns on, so most of them are
// near misses: two @s, an empty side, a domain one character off. The
// pattern is one of a few, broken ones among them.
describe("assertAllowedEmail, over random emails and patterns", () => {
  const seed = propertySeed();
  const ALPHABET = [
    "a",
    "@",
    ".",
    "-",
    "p",
    "0",
    "d",
    "e",
    "v",
    "P",
    "D",
    "x",
    '"',
    " ",
  ];
  // [the variable's value, the domains it allows, or undefined for none]
  const PATTERNS: [string | undefined, Set<string> | undefined][] = [
    ["p0\\.dev|p0security\\.com", new Set(["p0.dev", "p0security.com"])],
    [" p0\\.dev\n", new Set(["p0.dev"])],
    ["(dev|p0)\\.p0\\.dev", new Set(["dev.p0.dev", "p0.p0.dev"])],
    [undefined, undefined],
    ["  ", undefined],
    ["p0\\.(dev", undefined],
    ["p0\\.dev)|(evil\\.com", undefined],
  ];

  it(
    `refuses with its own error exactly what the rule refuses, and repeats the email only where INT-231 does (PROPERTY_SEED=${seed})`,
    // Thousands of cases, which a loaded machine can take seconds over.
    { timeout: 30_000 },
    () => {
      const log = recordLogger();
      const random = seededRandom(seed);
      const pick = <T>(items: readonly T[]): T => {
        const item = items[Math.floor(random() * items.length)];
        if (item === undefined) throw new Error("picked from no items");
        return item;
      };
      for (let i = 0; i < 3000; i++) {
        const [pattern, domains] = pick(PATTERNS);
        withPattern(pattern);
        // Half of them end in a domain some pattern allows, in any case.
        const tail =
          random() < 0.5
            ? `@${pick(["p0.dev", "P0.Dev", "p0security.com", "dev.p0.dev", "evil.com"])}`
            : "";
        const email =
          Array.from({ length: Math.floor(random() * 12) }, () =>
            pick(ALPHABET)
          ).join("") + tail;
        const [local, domain, ...rest] = email.split("@");
        const allowed =
          domains !== undefined &&
          rest.length === 0 &&
          !!local &&
          domains.has(domain?.toLowerCase() ?? "");
        const where = `${JSON.stringify(email)} against ${JSON.stringify(pattern)}`;

        let outcome: unknown;
        try {
          check(email);
        } catch (error) {
          outcome = error;
        }

        if (allowed) {
          expect(outcome, where).toBeUndefined();
          continue;
        }
        if (!(outcome instanceof ConnectorError)) {
          throw new Error(`expected a ConnectorError for ${where}`);
        }
        if (domains === undefined) {
          expect(outcome.data.type, where).toBe("validation_error");
          expect(outcome.data.payload, where).toEqual({
            reason: "domain_pattern_unusable",
          });
          // One of two fixed messages, so nothing of the email is in it. (A
          // check that the message doesn't contain the email fails by
          // accident: "ve a" is in "receive access".)
          const unset = pattern === undefined || pattern.trim() === "";
          expect(outcome.data.message, where).toBe(
            `The Harbor connector refuses every request: ALLOWED_EMAIL_DOMAIN_PATTERN ${
              unset
                ? "isn't set"
                : "isn't a regular expression that compiles (the connector's log says why)"
            }. Set it on the connector to a regular expression for the email domains that may receive access.`
          );
        } else {
          // INT-231's message is the one place the email appears.
          expect(outcome.data, where).toEqual({
            type: "validation_error",
            message: `${email} isn't in an email domain this Harbor connector allows.`,
            payload: { reason: "domain_not_allowed" },
          });
        }
      }
      // A log line never carries the email: the only ones are a broken
      // pattern's, and they carry the pattern's problem alone.
      for (const [fields] of log.lines()) {
        expect(Object.keys(fields as object)).toEqual(["problem"]);
      }
    }
  );
});
