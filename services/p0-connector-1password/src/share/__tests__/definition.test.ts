import { describe, expect, it } from "vitest";

import { shareOutput } from "../definition.ts";

describe("shareOutput", () => {
  const SHARED = {
    link: "https://share.1password.com/s#abc",
    expiresAt: "2026-10-16T00:00:00.000Z",
    oneTimeOnly: false,
  };

  it("parses a link and when it expires", () => {
    expect(shareOutput.parse(SHARED)).toEqual(SHARED);
  });

  it.each([
    ["an empty link", { ...SHARED, link: "" }],
    ["no link", { ...SHARED, link: undefined }],
    ["an expiry that isn't a time", { ...SHARED, expiresAt: "tomorrow" }],
    // An old connector's answer, which can't say whether it opens once.
    ["no word on whether it opens once", { ...SHARED, oneTimeOnly: undefined }],
  ])("refuses %s", (_case, answer) => {
    expect(() => shareOutput.parse(answer)).toThrow();
  });
});
