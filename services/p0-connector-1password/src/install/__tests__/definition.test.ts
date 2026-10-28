import { describe, expect, it } from "vitest";

import { installValidation } from "../definition.ts";

const VALIDATION = {
  vaultCount: 2,
  sharingChecked: true,
  allowedDomains: "^acme\\.com$",
};

describe("installValidation", () => {
  it("parses the facts of an install that works", () => {
    expect(installValidation.parse(VALIDATION)).toEqual(VALIDATION);
  });

  it.each(["vaultCount", "sharingChecked", "allowedDomains"])(
    "refuses an answer without %s",
    (field) => {
      expect(() =>
        installValidation.parse({ ...VALIDATION, [field]: undefined })
      ).toThrow();
    }
  );

  // An install whose service account sees no vault fails its check instead.
  it("refuses an answer with no vaults", () => {
    expect(() =>
      installValidation.parse({ ...VALIDATION, vaultCount: 0 })
    ).toThrow();
  });
});
