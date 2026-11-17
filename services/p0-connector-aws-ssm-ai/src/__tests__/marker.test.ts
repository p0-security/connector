import { describe, expect, it } from "vitest";

import { markerFor } from "../marker.ts";
import { MARKER_PATTERN } from "../script/provision.ts";

describe("markerFor", () => {
  it("gives the same marker for the same secret name", () => {
    expect(markerFor("p0/ssh-ai/one")).toBe(markerFor("p0/ssh-ai/one"));
    // The first 32 hex digits of `printf p0/ssh-ai/one | shasum -a 256`.
    expect(markerFor("p0/ssh-ai/one")).toBe("5874dafbee1cac44a66e9e4b18208280");
  });

  it("gives different markers for names that differ", () => {
    const names = ["p0/ssh-ai/one", "p0/ssh-ai/one/", "p0/ssh-ai/One", "p0"];
    expect(new Set(names.map(markerFor)).size).toBe(names.length);
  });

  it.each(["a", "p0/ssh-ai/i-0123456789abcdef0/alice-ai", "x".repeat(512)])(
    "gives a marker the script accepts for %j",
    (name) => {
      const marker = markerFor(name);
      expect(marker).toHaveLength(32);
      expect(MARKER_PATTERN.test(marker)).toBe(true);
    }
  );
});
