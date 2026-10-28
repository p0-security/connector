import { describe, expect, it } from "vitest";

import { propertySeed, seededRandom } from "../../__tests__/fixtures.ts";
import {
  MINIMUM_HARBOR_VERSION,
  formatHarborVersion,
  isSupportedHarborVersion,
  parseHarborVersion,
} from "../version.ts";

describe("parseHarborVersion", () => {
  // `<VERSION file>-<8 hex of the commit>`, from Harbor's Makefile.
  it.each<[text: string, version: [number, number, number]]>([
    ["v2.14.0-44a74424", [2, 14, 0]],
    ["v2.12.0-9da38ae0", [2, 12, 0]],
    ["2.13.1", [2, 13, 1]],
    ["v10.0.12-rc1", [10, 0, 12]],
    ["v2.12.0+build.7", [2, 12, 0]],
  ])("reads %s", (text, [major, minor, patch]) => {
    expect(parseHarborVersion(text)).toEqual({ major, minor, patch });
  });

  it.each([
    "",
    "v2",
    "v2.12",
    "2.12.x",
    "version 2.12.0",
    " v2.12.0",
    "v2.12.0.1",
    "v2.12.01234567",
    "latest",
    "v-2.12.0",
    "V2.12.0",
    "v2.12.0\n",
    "v2.12.0\t",
    "v2.12.0 x",
    "v2.12.0-<script>",
    `v2.12.0-${"a".repeat(65)}`,
  ])("refuses %j", (text) => {
    expect(parseHarborVersion(text)).toBeUndefined();
  });
});

describe("isSupportedHarborVersion", () => {
  it("has 2.12.0 as the floor", () => {
    expect(formatHarborVersion(MINIMUM_HARBOR_VERSION)).toBe("2.12.0");
  });

  it.each<[text: string, supported: boolean]>([
    ["v2.12.0", true],
    ["v2.12.4", true],
    ["v2.13.0", true],
    ["v3.0.0", true],
    ["v2.11.9", false],
    ["v2.9.99", false],
    ["v1.99.99", false],
  ])("%s: %s", (text, supported) => {
    const version = parseHarborVersion(text);
    expect(version && isSupportedHarborVersion(version)).toBe(supported);
  });
});

// A version is supported exactly when it is the floor or later in release
// order, whatever suffix follows the three numbers, and a string that isn't
// three numbers with an optional `v` and suffix isn't a version.
const seed = propertySeed();
it(
  `orders versions as releases do, and reads only a whole version (PROPERTY_SEED=${seed})`,
  { timeout: 30_000 },
  () => {
    const random = seededRandom(seed);
    // Mostly near the floor, where the order is decided.
    const part = (near: number) =>
      random() < 0.7
        ? Math.max(0, near - 2 + Math.floor(random() * 5))
        : Math.floor(random() * 1_000_000);
    const pick = <T>(items: readonly T[]): T => {
      const item = items[Math.floor(random() * items.length)];
      if (item === undefined) throw new Error("picked from no items");
      return item;
    };
    const floor = MINIMUM_HARBOR_VERSION;
    for (let i = 0; i < 3000; i++) {
      const [major, minor, patch] = [
        part(floor.major),
        part(floor.minor),
        part(floor.patch + 2),
      ];
      const text = `${pick(["v", ""])}${major}.${minor}.${patch}${pick(["", "-44a74424", "-rc1", "+build"])}`;

      const version = parseHarborVersion(text);

      if (
        version?.major !== major ||
        version.minor !== minor ||
        version.patch !== patch
      ) {
        throw new Error(`read ${JSON.stringify(version)} from ${text}`);
      }
      // Release order, written out apart from the code under test: compare
      // the first part that differs from the floor's.
      const pairs: [number, number][] = [
        [major, floor.major],
        [minor, floor.minor],
        [patch, floor.patch],
      ];
      const [mine, theirs] = pairs.find(([a, b]) => a !== b) ?? [0, 0];
      const later = mine >= theirs;
      if (isSupportedHarborVersion(version) !== later) {
        throw new Error(`${text} supported: ${!later}`);
      }
      // Not a version: something before or after it, two parts, or four.
      for (const broken of [
        `x${text}`,
        `${text} x`,
        `${text}\n`,
        `${major}.${minor}`,
        `${major}.${minor}.${patch}.1`,
      ]) {
        if (parseHarborVersion(broken) !== undefined) {
          throw new Error(`read a version from ${JSON.stringify(broken)}`);
        }
      }
    }
  }
);
