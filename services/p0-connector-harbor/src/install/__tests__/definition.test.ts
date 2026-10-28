import { describe, expect, it } from "vitest";

import { installValidation } from "../definition.ts";

const FACTS = {
  harborVersion: "v2.14.0-44a74424",
  authMode: "oidc_auth",
  allowedEmailDomainPattern: "example\\.com|example\\.org",
};

describe("installValidation", () => {
  it("is the instance's version and auth mode, and the connector's domain pattern", () => {
    expect(installValidation.parse(FACTS)).toEqual(FACTS);
  });

  it.each(Object.keys(FACTS))("requires %s", (field) => {
    const { [field]: _omitted, ...rest }: Record<string, unknown> = FACTS;
    expect(() => installValidation.parse(rest)).toThrow();
  });

  // Install validation succeeds only when it has all three to report.
  it.each(Object.keys(FACTS))("rejects an empty %s", (field) => {
    expect(() => installValidation.parse({ ...FACTS, [field]: "" })).toThrow();
  });

  // Which modes are supported is the connector's call, so a mode this schema
  // has never heard of still parses.
  it("takes any auth mode", () => {
    const facts = { ...FACTS, authMode: "some_future_auth" };
    expect(installValidation.parse(facts)).toEqual(facts);
  });

  // A robot account's expiry was a fact once. The admin credential has no
  // expiry to report, so a field P0 no longer reads is dropped.
  it("drops a robotExpiresAt", () => {
    expect(
      installValidation.parse({
        ...FACTS,
        robotExpiresAt: "2027-01-01T00:00:00Z",
      })
    ).toEqual(FACTS);
  });
});
