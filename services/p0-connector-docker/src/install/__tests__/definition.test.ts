import { describe, expect, it } from "vitest";

import { installValidation } from "../definition.ts";

const VALIDATION = {
  tokenAccepted: true,
  canReadMembers: true,
  canInvite: false,
  allowedDomains: "^example\\.com$",
};

// P0 reads the connector's answer with this, and stores what it read.
describe("the install validation", () => {
  it("keeps the three checks and the pattern as the connector reported them", () => {
    expect(installValidation.parse(VALIDATION)).toEqual(VALIDATION);
  });

  it.each(Object.keys(VALIDATION))("requires %s", (field) => {
    const withoutIt = Object.fromEntries(
      Object.entries(VALIDATION).filter(([key]) => key !== field)
    );
    expect(() => installValidation.parse(withoutIt)).toThrow();
  });

  // P0 shows each check as passed or failed, so each has to be one of the two.
  it.each(["tokenAccepted", "canReadMembers", "canInvite"])(
    "rejects %s when it isn't a boolean",
    (check) => {
      for (const value of ["true", 1, null]) {
        expect(() =>
          installValidation.parse({ ...VALIDATION, [check]: value })
        ).toThrow();
      }
    }
  );

  it("rejects a pattern that isn't a string", () => {
    for (const allowedDomains of [null, 1, [VALIDATION.allowedDomains]]) {
      expect(() =>
        installValidation.parse({ ...VALIDATION, allowedDomains })
      ).toThrow();
    }
  });
});
