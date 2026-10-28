// copy of services/p0-connector-harbor/src/harbor/__tests__/version.test.ts,
// for Argo CD's versions and its 3.0.0 floor
import { describe, expect, it } from "vitest";

import { propertySeed, seededRandom } from "../../__tests__/fixtures.ts";
import {
  MINIMUM_ARGOCD_VERSION,
  formatArgoCdVersion,
  isSupportedArgoCdVersion,
  parseArgoCdVersion,
} from "../version.ts";

describe("parseArgoCdVersion", () => {
  // `v<VERSION file>+<7 hex of the commit>`, from Argo CD's Makefile, with a
  // pre-release before the `+` for a release candidate.
  it.each<[text: string, version: [number, number, number]]>([
    ["v3.5.5+2f9b0d1", [3, 5, 5]],
    ["v3.0.0+e98f483", [3, 0, 0]],
    ["v3.1.0-rc1+8d1e2a0", [3, 1, 0]],
    ["v2.14.11+8283115", [2, 14, 11]],
    ["3.2.1", [3, 2, 1]],
    ["v10.0.12-rc1", [10, 0, 12]],
  ])("reads %s", (text, [major, minor, patch]) => {
    expect(parseArgoCdVersion(text)).toEqual({ major, minor, patch });
  });

  it.each([
    "",
    "v3",
    "v3.5",
    "3.5.x",
    "version 3.5.5",
    " v3.5.5",
    "v3.5.5.1",
    "v3.5.01234567",
    "latest",
    "v-3.5.5",
    "V3.5.5",
    "v3.5.5\n",
    "v3.5.5\t",
    "v3.5.5 x",
    "v3.5.5+<script>",
    `v3.5.5+${"a".repeat(65)}`,
  ])("refuses %j", (text) => {
    expect(parseArgoCdVersion(text)).toBeUndefined();
  });
});

describe("isSupportedArgoCdVersion", () => {
  it("has 3.0.0 as the floor", () => {
    expect(formatArgoCdVersion(MINIMUM_ARGOCD_VERSION)).toBe("3.0.0");
  });

  it.each<[text: string, supported: boolean]>([
    ["v3.0.0+e98f483", true],
    ["v3.0.1", true],
    ["v3.5.5", true],
    ["v4.0.0", true],
    ["v2.14.11+8283115", false],
    ["v2.99.99", false],
    ["v1.8.7", false],
  ])("%s: %s", (text, supported) => {
    const version = parseArgoCdVersion(text);
    expect(version && isSupportedArgoCdVersion(version)).toBe(supported);
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
    const floor = MINIMUM_ARGOCD_VERSION;
    for (let i = 0; i < 3000; i++) {
      const [major, minor, patch] = [
        part(floor.major),
        part(floor.minor + 2),
        part(floor.patch + 2),
      ];
      const text = `${pick(["v", ""])}${major}.${minor}.${patch}${pick(["", "+2f9b0d1", "-rc1", "-rc2+8d1e2a0"])}`;

      const version = parseArgoCdVersion(text);

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
      if (isSupportedArgoCdVersion(version) !== later) {
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
        if (parseArgoCdVersion(broken) !== undefined) {
          throw new Error(`read a version from ${JSON.stringify(broken)}`);
        }
      }
    }
  }
);
