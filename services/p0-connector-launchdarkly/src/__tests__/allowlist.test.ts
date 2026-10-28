import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DOMAIN_ALLOW_PATTERN_ENV,
  compileAllowlist,
  validateAllowedEmail,
} from "../allowlist.ts";
import { connectorError, logger, recordLogger } from "./fixtures.ts";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

const withPattern = (pattern: string | undefined) =>
  vi.stubEnv(DOMAIN_ALLOW_PATTERN_ENV, pattern);

const check = (email: string) => validateAllowedEmail(email, logger);

/** The `ConnectorError` `validateAllowedEmail` refuses `email` with. */
const refusal = (email: string) => connectorError(async () => check(email));

describe("compileAllowlist", () => {
  it("reads DOMAIN_ALLOW_PATTERN, and keeps it trimmed", () => {
    withPattern(" p0\\.dev|p0security\\.com\n");
    expect(compileAllowlist()).toEqual({
      ok: true,
      pattern: "p0\\.dev|p0security\\.com",
      regex: /^(?:p0\.dev|p0security\.com)$/i,
    });
  });

  it.each([
    ["unset", undefined, { reason: "unset" }],
    ["blank", " \t\n", { reason: "unset" }],
    [
      "not a regex",
      "p0\\.(dev",
      {
        reason: "invalid_regex",
        detail: "Invalid regular expression: /p0\\.(dev/: Unterminated group",
      },
    ],
    // Wrapped, this one compiles, to `^(?:p0\.dev)|(evil\.com)$`.
    [
      "a regex only once it is wrapped",
      "p0\\.dev)|(evil\\.com",
      {
        reason: "invalid_regex",
        detail:
          "Invalid regular expression: /p0\\.dev)|(evil\\.com/: Unmatched ')'",
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

describe("validateAllowedEmail", () => {
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
    ["a subdomain the pattern doesn't name", "alice@eng.p0.dev"],
    ["an address with two @s", "mallory@evil.io@p0.dev"],
    ["an address with no @", "alice"],
  ])("refuses %s, without repeating the email", async (_case, email) => {
    withPattern("p0\\.dev|p0security\\.com");

    const { data } = await refusal(email);

    expect(data).toEqual({
      type: "validation_error",
      message:
        "The requester's email isn't in an email domain this LaunchDarkly connector allows. Ask your P0 admin which domains it allows.",
      payload: { reason: "domain_not_allowed" },
    });
  });

  it.each([
    ["unset", undefined, "DOMAIN_ALLOW_PATTERN isn't set"],
    [
      "not a regex that compiles",
      "p0\\.(dev",
      "DOMAIN_ALLOW_PATTERN isn't a regular expression that compiles (the connector's log says why)",
    ],
  ])(
    "refuses every email when the pattern is %s, and logs why without the email",
    async (_case, pattern, problem) => {
      const log = recordLogger();
      withPattern(pattern);

      const { data } = await refusal("alice@p0.dev");

      expect(data).toEqual({
        type: "validation_error",
        message: `The LaunchDarkly connector refuses every request: ${problem}. Set it on the connector to a regular expression for the email domains that may receive access.`,
        payload: { reason: "domain_pattern_unusable" },
      });
      expect(log.seen(data)).not.toContain("alice");
    }
  );

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
