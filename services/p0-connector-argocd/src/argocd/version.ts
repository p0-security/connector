// copy of services/p0-connector-harbor/src/harbor/version.ts, for Argo CD's
// `Version` and its 3.0.0 floor

/** An Argo CD release, as its `Version` starts: `v3.5.5+2f9b0d1`. */
type ArgoCdVersion = { major: number; minor: number; patch: number };

/**
 * The first Argo CD the connector supports: v3's fine-grained
 * `applications, update/<group>/<kind>/<ns>/<name>` policy is what lets the
 * `p0-connector` account patch `argocd-rbac-cm` and nothing else.
 */
export const MINIMUM_ARGOCD_VERSION: ArgoCdVersion = {
  major: 3,
  minor: 0,
  patch: 0,
};

// `v<VERSION file>+<7 hex of the commit>`: `v3.5.5+2f9b0d1`, with a
// pre-release such as `-rc1` before the `+`. Up to six digits a part, so each
// reads exactly as a number, and a tail of at most 64 of the characters a
// build or pre-release suffix is written in. The whole string has to match,
// since P0 is handed it as a fact.
const VERSION =
  /^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:[-+][0-9A-Za-z.+-]{0,64})?$/;

/**
 * The release `Version` names, or `undefined` when the string isn't one:
 * three numbers, with an optional `v` before and an optional suffix after.
 */
export const parseArgoCdVersion = (text: string): ArgoCdVersion | undefined => {
  const match = VERSION.exec(text);
  if (!match) return undefined;
  const [, major, minor, patch] = match;
  return {
    major: Number(major),
    minor: Number(minor),
    patch: Number(patch),
  };
};

/** `3.0.0`, for a message. */
export const formatArgoCdVersion = ({ major, minor, patch }: ArgoCdVersion) =>
  `${major}.${minor}.${patch}`;

/** Whether `version` is {@link MINIMUM_ARGOCD_VERSION} or later. */
export const isSupportedArgoCdVersion = (version: ArgoCdVersion): boolean => {
  const floor = MINIMUM_ARGOCD_VERSION;
  if (version.major !== floor.major) return version.major > floor.major;
  if (version.minor !== floor.minor) return version.minor > floor.minor;
  return version.patch >= floor.patch;
};
