/** A Harbor release, as its `harbor_version` starts: `v2.14.0-44a74424`. */
type HarborVersion = { major: number; minor: number; patch: number };

/**
 * The oldest Harbor the connector supports. It was set by what the robot
 * account the connector once used could hold (INT-233, Harbor PR #20754),
 * and is kept as the floor the connector's Harbor research (INT-255, INT-265)
 * was read against: an ID token on Harbor's API is older than it.
 */
export const MINIMUM_HARBOR_VERSION: HarborVersion = {
  major: 2,
  minor: 12,
  patch: 0,
};

// `<VERSION file>-<8 hex of the commit>`: `v2.14.0-44a74424`. Up to six
// digits a part, so each reads exactly as a number, and a tail of at most 64
// of the characters a build or pre-release suffix is written in. The whole
// string has to match, since P0 is handed it as a fact.
const VERSION =
  /^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:[-+][0-9A-Za-z.+-]{0,64})?$/;

/**
 * The release `harbor_version` names, or `undefined` when the string isn't
 * one: three numbers, with an optional `v` before and an optional suffix
 * after.
 */
export const parseHarborVersion = (text: string): HarborVersion | undefined => {
  const match = VERSION.exec(text);
  if (!match) return undefined;
  const [, major, minor, patch] = match;
  return {
    major: Number(major),
    minor: Number(minor),
    patch: Number(patch),
  };
};

/** `2.12.0`, for a message. */
export const formatHarborVersion = ({ major, minor, patch }: HarborVersion) =>
  `${major}.${minor}.${patch}`;

/** Whether `version` is {@link MINIMUM_HARBOR_VERSION} or later. */
export const isSupportedHarborVersion = (version: HarborVersion): boolean => {
  const floor = MINIMUM_HARBOR_VERSION;
  if (version.major !== floor.major) return version.major > floor.major;
  if (version.minor !== floor.minor) return version.minor > floor.minor;
  return version.patch >= floor.patch;
};
