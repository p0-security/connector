import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { parseAllowedDomains } from "../allowed-domains.ts";
import { ALLOWED_PATTERN, EMAIL } from "./fixtures.ts";

describe("parseAllowedDomains", () => {
  // The GCP and Entra perimeters take an unset pattern as "every domain".
  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["blank", "  \n"],
  ])("refuses a %s pattern", (_case, pattern) => {
    expect(() => parseAllowedDomains(pattern)).toThrow(
      "DOMAIN_ALLOW_PATTERN isn't set, or is blank."
    );
  });

  it.each(["(", "[a-", "a{2,1}", "\\"])(
    "refuses %s, which isn't a regular expression",
    (pattern) => {
      expect(() => parseAllowedDomains(pattern)).toThrow(
        "DOMAIN_ALLOW_PATTERN isn't a valid regular expression"
      );
    }
  );

  // The regex engine's own error says where the pattern goes wrong.
  it("keeps the regex engine's error as the cause", () => {
    expect(() => parseAllowedDomains("(")).toThrow(
      expect.objectContaining({ cause: expect.any(SyntaxError) })
    );
  });

  // `RegExp#source` would escape the slash.
  it("keeps the pattern as written, for the install to display", () => {
    expect(parseAllowedDomains("a/b").pattern).toBe("a/b");
  });

  // Left in, the newline would compile and then match no domain at all.
  it("drops the whitespace a heredoc leaves around the pattern", () => {
    const allowedDomains = parseAllowedDomains(`  ${ALLOWED_PATTERN}\n`);

    expect(allowedDomains.pattern).toBe(ALLOWED_PATTERN);
    expect(allowedDomains.allows(EMAIL)).toBe(true);
  });
});

describe("allows", () => {
  const anchored = parseAllowedDomains("^acme\\.com$");

  it("tests the email's domain, the part after the @", () => {
    expect(anchored.allows("alice@acme.com")).toBe(true);
    expect(anchored.allows("acme.com@evil.com")).toBe(false);
  });

  it.each([
    ["another domain", "alice@evil.com"],
    ["a subdomain", "alice@eu.acme.com"],
    ["a domain that ends with it", "alice@notacme.com"],
    ["a domain that starts with it", "alice@acme.com.evil.com"],
  ])("an anchored pattern refuses %s", (_case, email) => {
    expect(anchored.allows(email)).toBe(false);
  });

  // The pattern runs as the customer wrote it. Anchoring it is up to them.
  it("an unanchored pattern matches anywhere in the domain", () => {
    const unanchored = parseAllowedDomains("acme\\.com");

    expect(unanchored.allows("alice@notacme.com")).toBe(true);
    expect(unanchored.allows("alice@acme.com.evil.com")).toBe(true);
    expect(unanchored.allows("alice@evil.com")).toBe(false);
  });

  // Domain names ignore case, and so does the pattern.
  it("ignores case", () => {
    expect(anchored.allows("alice@ACME.com")).toBe(true);
    expect(anchored.allows("Alice@Acme.Com")).toBe(true);
  });

  it.each([
    ["no @", "acme.com"],
    ["nothing after the @", "alice@"],
    ["two @", "alice@acme.com@acme.com"],
    ["an empty string", ""],
  ])(
    "refuses an address with %s, even when the pattern matches anything",
    (_case, email) => {
      expect(parseAllowedDomains(".*").allows(email)).toBe(false);
    }
  );
});

describe("requireAllowedDomains", () => {
  beforeEach(() => {
    // Each test reads the environment afresh, as a new process would.
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("reads DOMAIN_ALLOW_PATTERN from the environment", async () => {
    vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);
    const { requireAllowedDomains } = await import("../allowed-domains.ts");

    expect(requireAllowedDomains().pattern).toBe(ALLOWED_PATTERN);
  });

  it("throws when it isn't set", async () => {
    vi.stubEnv("DOMAIN_ALLOW_PATTERN", undefined);
    const { requireAllowedDomains } = await import("../allowed-domains.ts");

    expect(() => requireAllowedDomains()).toThrow(
      "DOMAIN_ALLOW_PATTERN isn't set, or is blank."
    );
  });

  // The pattern is the deployment's, fixed when the connector starts.
  it("parses it once, whatever the environment says later", async () => {
    vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);
    const { requireAllowedDomains } = await import("../allowed-domains.ts");
    const first = requireAllowedDomains();

    vi.stubEnv("DOMAIN_ALLOW_PATTERN", ".*");

    expect(requireAllowedDomains()).toBe(first);
  });
});
