import { describe, expect, it, vi } from "vitest";

import {
  DOMAIN_PATTERN_ENV,
  assertDomainPatternIsValid,
  emailDomainIsAllowed,
  verifyEmailDomain,
} from "../domain.ts";
import { resetBetweenTests } from "./http.ts";

resetBetweenTests();

/** Whether `email` passes with `DOMAIN_PATTERN` set to `pattern`. */
const allowedBy = (pattern: string | undefined, email: string) => {
  vi.stubEnv(DOMAIN_PATTERN_ENV, pattern);
  return emailDomainIsAllowed(email);
};

describe("emailDomainIsAllowed", () => {
  describe("fails closed when unconfigured", () => {
    it("refuses every user when the variable is unset", () => {
      expect(allowedBy(undefined, "alice@example.com")).toBe(false);
    });

    it.each(["", "   "])("refuses every user for the pattern %j", (pattern) => {
      expect(allowedBy(pattern, "alice@example.com")).toBe(false);
    });

    it("refuses every user when the pattern isn't a valid regex", () => {
      expect(allowedBy("(example", "alice@example.com")).toBe(false);
    });
  });

  it("reads the pattern from DOMAIN_PATTERN", () => {
    vi.stubEnv(DOMAIN_PATTERN_ENV, "example\\.com");
    expect(emailDomainIsAllowed("alice@example.com")).toBe(true);
    expect(emailDomainIsAllowed("alice@other.com")).toBe(false);
  });

  it("follows a change to DOMAIN_PATTERN", () => {
    expect(allowedBy("example\\.com", "alice@example.com")).toBe(true);
    expect(allowedBy("other\\.com", "alice@example.com")).toBe(false);
  });

  it("ignores whitespace around the pattern", () => {
    expect(allowedBy(" example\\.com\n", "alice@example.com")).toBe(true);
  });

  describe("anchors the pattern to the whole domain", () => {
    const pattern = "example\\.com";

    it("accepts the exact domain", () => {
      expect(allowedBy(pattern, "alice@example.com")).toBe(true);
    });

    it("rejects a domain that merely ends with the pattern", () => {
      expect(allowedBy(pattern, "alice@evil-example.com")).toBe(false);
    });

    it("rejects a domain that merely starts with the pattern", () => {
      expect(allowedBy(pattern, "alice@example.com.evil.io")).toBe(false);
    });

    it("anchors both sides of an alternation", () => {
      vi.stubEnv(DOMAIN_PATTERN_ENV, "example\\.com|example\\.org");
      expect(emailDomainIsAllowed("a@example.org")).toBe(true);
      expect(emailDomainIsAllowed("a@example.com")).toBe(true);
      expect(emailDomainIsAllowed("a@example.com.evil.io")).toBe(false);
      expect(emailDomainIsAllowed("a@evil-example.org")).toBe(false);
    });

    it("matches the domain only, not the local part", () => {
      expect(allowedBy(pattern, "example.com@evil.io")).toBe(false);
    });

    it("matches an Entra guest's UPN by the domain after the @", () => {
      const guest = "alice_example.com#EXT#@contoso.onmicrosoft.com";
      expect(allowedBy(pattern, guest)).toBe(false);
      expect(allowedBy("contoso\\.onmicrosoft\\.com", guest)).toBe(true);
    });
  });

  describe("subdomains follow the regex exactly", () => {
    it("rejects a subdomain the pattern doesn't name", () => {
      expect(allowedBy("example\\.com", "alice@sub.example.com")).toBe(false);
    });

    it("accepts a subdomain when the pattern allows one", () => {
      vi.stubEnv(DOMAIN_PATTERN_ENV, "(.+\\.)?example\\.com");
      expect(emailDomainIsAllowed("alice@sub.example.com")).toBe(true);
      expect(emailDomainIsAllowed("alice@example.com")).toBe(true);
      expect(emailDomainIsAllowed("alice@evil-example.com")).toBe(false);
    });

    it("accepts only the subdomain a pattern names", () => {
      vi.stubEnv(DOMAIN_PATTERN_ENV, "eng\\.example\\.com");
      expect(emailDomainIsAllowed("alice@eng.example.com")).toBe(true);
      expect(emailDomainIsAllowed("alice@example.com")).toBe(false);
    });
  });

  it("matches the domain case-insensitively", () => {
    expect(allowedBy("example\\.com", "Alice@Example.COM")).toBe(true);
  });

  it("matches the pattern case-insensitively", () => {
    expect(allowedBy("Example\\.COM", "alice@example.com")).toBe(true);
  });

  it.each(["alice", "alice@", "@example.com", "a@b@example.com"])(
    "refuses the malformed address %j",
    (email) => {
      expect(allowedBy(".*", email)).toBe(false);
    }
  );
});

describe("verifyEmailDomain", () => {
  const verify = (alreadyGranted: boolean) =>
    verifyEmailDomain({
      email: "alice@example.com",
      requestId: "req",
      alreadyGranted,
    });

  it.each([false, true])(
    "passes a user whose domain matches (alreadyGranted: %s)",
    (alreadyGranted) => {
      vi.stubEnv(DOMAIN_PATTERN_ENV, "example\\.com");
      expect(verify(alreadyGranted)).toBe(true);
    }
  );

  it("refuses a user outside the pattern with a validation_error naming DOMAIN_PATTERN", () => {
    vi.stubEnv(DOMAIN_PATTERN_ENV, "example\\.com");
    expect(() =>
      verifyEmailDomain({
        email: "mallory@evil.example",
        requestId: "req",
        alreadyGranted: false,
      })
    ).toThrow(
      expect.objectContaining({
        message:
          "Domain verification refused mallory@evil.example: DOMAIN_PATTERN on the connector must match the whole domain after the @.",
        data: expect.objectContaining({ type: "validation_error" }),
      })
    );
  });

  it.each([
    [undefined, "DOMAIN_PATTERN is not set"],
    ["(example", "DOMAIN_PATTERN is not a valid regex"],
  ])(
    "says domain verification isn't configured when the pattern is %j",
    (pattern, problem) => {
      vi.stubEnv(DOMAIN_PATTERN_ENV, pattern);
      for (const check of [
        () => verify(false),
        () => assertDomainPatternIsValid("req"),
      ]) {
        expect(check).toThrow(
          expect.objectContaining({
            message: `Domain verification is not configured: ${problem}. Set DOMAIN_PATTERN on the connector to a regex of the email domains P0 may grant to.`,
            data: expect.objectContaining({ type: "validation_error" }),
          })
        );
      }
    }
  );

  it.each([
    ["the pattern no longer matches", "other\\.com"],
    ["the pattern is unset", undefined],
    ["the pattern isn't a valid regex", "(example"],
  ])(
    "reports false without throwing for a user P0 already granted to when %s",
    (_, pattern) => {
      vi.stubEnv(DOMAIN_PATTERN_ENV, pattern);
      expect(verify(true)).toBe(false);
    }
  );
});
