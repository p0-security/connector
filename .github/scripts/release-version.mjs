// Shared by the release scripts. A connector release is a plain x.y.z, pushed
// as the git tag vx.y.z and written into every services/*/package.json. The
// root package.json and packages/* are versioned separately and never touched.
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// Plain x.y.z with no leading zeros. No prerelease or build metadata: the
// app's release catalog lists none, and publish.yaml forbids them for NPM.
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

// Any semver tag, prerelease and build metadata included, so a hand-pushed
// v1.2.0-rc.1 still blocks a release at or below it.
const TAG =
  /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

// The top-level "version" field, two spaces in as prettier writes it. Nested
// objects are indented further, so they never match.
const VERSION_LINE = /^ {2}"version": "[^"]*"/gm;

/** Returns [major, minor, patch] as BigInts, or null if not a plain x.y.z. */
export const parseVersion = (version) => {
  const match = VERSION.exec(version);
  return match ? match.slice(1, 4).map(BigInt) : null;
};

/** Returns { core, prerelease } for a semver tag, or null for any other tag. */
export const parseTag = (tag) => {
  const match = TAG.exec(tag);
  return match
    ? { core: match.slice(1, 4).map(BigInt), prerelease: match[4] }
    : null;
};

const compareCore = (a, b) => {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i] ? 1 : -1;
  }
  return 0;
};

/**
 * Whether the plain x.y.z `version` is strictly above the semver tag, by
 * semver precedence: 1.2.0 is above v1.2.0-rc.1 but not above v1.2.0.
 */
export const isAboveTag = (version, tag) => {
  const order = compareCore(version, tag.core);
  return order > 0 || (order === 0 && tag.prerelease !== undefined);
};

/**
 * The reasons `version` cannot be released, given every v* tag name and the
 * versions main's services report today. Empty when it can.
 */
export const releaseVersionErrors = (version, tags, currentVersions = []) => {
  const parsed = parseVersion(version);
  if (!parsed) return [`version must be a plain x.y.z (got "${version}")`];

  const errors = [];
  if (tags.includes(`v${version}`)) errors.push(`v${version} already exists`);

  // The highest tag at or above the version, so the message names one.
  const blocking = tags
    .map((name) => ({ name, tag: parseTag(name) }))
    .filter(({ tag }) => tag && !isAboveTag(parsed, tag))
    .sort((a, b) => compareCore(b.tag.core, a.tag.core))[0];
  if (blocking) {
    errors.push(`${version} is not above ${blocking.name}`);
  }

  // Builds from main already report these, so a release at or below them
  // could not be told apart from an unreleased build.
  const current = currentVersions
    .map(parseVersion)
    .filter(Boolean)
    .sort((a, b) => compareCore(b, a))[0];
  if (current && compareCore(parsed, current) <= 0) {
    errors.push(
      `${version} is not above ${current.join(".")}, which services on main already report`
    );
  }
  return errors;
};

/** Paths of every services/*\/package.json under `root`, sorted. */
export const serviceManifests = (root = ".") =>
  readdirSync(join(root, "services"), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(root, "services", entry.name, "package.json"))
    .filter((path) => existsSync(path))
    .sort();

/**
 * Rewrites the top-level "version" of a package.json's text, leaving every
 * other byte as it is, so prettier's formatting survives.
 */
export const setVersion = (text, version) => {
  const matches = text.match(VERSION_LINE) ?? [];
  if (matches.length !== 1) {
    throw new Error(
      `expected one top-level "version" line, found ${matches.length}`
    );
  }
  return text.replace(VERSION_LINE, `  "version": "${version}"`);
};

/** { path, version } for every service package.json under `root`. */
export const readServiceVersions = (root = ".") =>
  serviceManifests(root).map((path) => ({
    path,
    version: JSON.parse(readFileSync(path, "utf8")).version,
  }));

/**
 * The services under `root` that writing `version` would move backwards, as
 * a stale re-run of the version-bump PR job would after a later release.
 */
export const downgradeErrors = (version, root = ".") => {
  const parsed = parseVersion(version);
  return readServiceVersions(root)
    .filter((entry) => {
      const current = parseVersion(entry.version);
      return parsed && current && compareCore(current, parsed) > 0;
    })
    .map(
      (entry) =>
        `${entry.path} is at ${entry.version}, above ${version}; refusing to lower it`
    );
};

/** Writes `version` into every service package.json under `root`. */
export const writeServiceVersions = (version, root = ".") => {
  const paths = serviceManifests(root);
  for (const path of paths) {
    writeFileSync(path, setVersion(readFileSync(path, "utf8"), version));
  }
  return paths;
};

/** The reasons the services under `root` are not all at `version`. */
export const serviceVersionErrors = (version, root = ".") => {
  if (!parseVersion(version)) {
    return [`version must be a plain x.y.z (got "${version}")`];
  }
  const versions = readServiceVersions(root);
  if (versions.length === 0) return ["found no services/*/package.json"];
  return versions
    .filter((entry) => entry.version !== version)
    .map((entry) => `${entry.path} is at ${entry.version}, not ${version}`);
};

/** Prints each error as a GitHub annotation and exits 1 if there are any. */
export const failOn = (errors) => {
  for (const error of errors) console.log(`::error::${error}`);
  if (errors.length > 0) process.exit(1);
};
