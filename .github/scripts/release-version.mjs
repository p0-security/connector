// Shared by the release scripts. A release is a plain x.y.z, tagged
// <tag prefix>/vx.y.z. The tag prefix names what is released and which
// package.json files hold its version, and a release is only ever compared
// with earlier tags of the same prefix.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";

// Plain x.y.z with no leading zeros. No prerelease or build metadata: the
// app's release catalog lists none, and NPM releases have never used them.
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

const serviceManifests = (root) =>
  readdirSync(join(root, "services"), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(root, "services", entry.name, "package.json"))
    .filter((path) => existsSync(path));

/**
 * Every tag prefix the release workflow handles, mapped to a function that
 * returns the package.json paths under a repo root that hold its version.
 */
export const TAG_PREFIXES = {
  // Every connector service. Images built from them report this version.
  connector: serviceManifests,
  // Published to NPM together, so they always share a version.
  npm: (root) =>
    ["connector-core", "connector-sdk"].map((name) =>
      join(root, "packages", name, "package.json")
    ),
};

/** The reasons `prefix` is not a tag prefix in TAG_PREFIXES. */
export const tagPrefixErrors = (prefix) =>
  Object.hasOwn(TAG_PREFIXES, prefix)
    ? []
    : [
        `tag prefix must be one of ${Object.keys(TAG_PREFIXES).join(", ")} (got "${prefix}")`,
      ];

/** Returns [major, minor, patch] as BigInts, or null if not a plain x.y.z. */
export const parseVersion = (version) => {
  const match = VERSION.exec(version);
  return match ? match.slice(1, 4).map(BigInt) : null;
};

const compare = (a, b) => {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i] ? 1 : -1;
  }
  return 0;
};

/**
 * { path, version } for each package.json under `root` that holds
 * `prefix`'s version, sorted by path. Paths are relative to `root`.
 */
export const readVersions = (prefix, root = ".") =>
  TAG_PREFIXES[prefix](root)
    .map((path) => ({
      path: relative(root, path),
      version: JSON.parse(readFileSync(path, "utf8")).version,
    }))
    .sort((a, b) => a.path.localeCompare(b.path));

/** The reasons `prefix`'s package.json files under `root` are not all at `version`. */
export const versionErrors = (prefix, version, root = ".") => {
  const versions = readVersions(prefix, root);
  if (versions.length === 0) return [`found no ${prefix} package.json files`];
  return versions
    .filter((entry) => entry.version !== version)
    .map((entry) => `${entry.path} is at ${entry.version}, not ${version}`);
};

/**
 * The reasons `prefix`'s package.json files under `root` don't all hold one
 * version. Each names a file off the most common version, so a service added
 * at an old version stands out.
 */
export const consistencyErrors = (prefix, root = ".") => {
  const versions = readVersions(prefix, root);
  const counts = new Map();
  for (const { version } of versions) {
    counts.set(version, (counts.get(version) ?? 0) + 1);
  }
  if (counts.size <= 1) return [];
  const [common] = [...counts].sort((a, b) => b[1] - a[1])[0];
  return versions
    .filter((entry) => entry.version !== common)
    .map(
      (entry) =>
        `${entry.path} is at ${entry.version}, but the other ${prefix} package.json files are at ${common}`
    );
};

/**
 * Parses `git ls-remote --tags` output into { name, commit } per tag, using
 * the peeled commit of an annotated tag.
 */
export const parseTags = (lsRemote) => {
  const commits = new Map();
  for (const line of lsRemote.split("\n").filter(Boolean)) {
    const [commit, ref] = line.split("\t");
    const name = ref.replace(/^refs\/tags\//, "");
    if (name.endsWith("^{}")) {
      commits.set(name.slice(0, -3), commit);
    } else if (!commits.has(name)) {
      commits.set(name, commit);
    }
  }
  return [...commits].map(([name, commit]) => ({ name, commit }));
};

/**
 * The reasons `<prefix>/v<version>` cannot tag `commit`, given every tag as
 * { name, commit }. Empty when the tag is free and above every earlier tag
 * with the same prefix, or already tags `commit` (a re-run).
 */
export const tagErrors = (prefix, version, commit, tags) => {
  const parsed = parseVersion(version);
  if (!parsed) return [`version must be a plain x.y.z (got "${version}")`];

  const name = `${prefix}/v${version}`;
  const existing = tags.find((tag) => tag.name === name);
  if (existing) {
    return existing.commit === commit
      ? []
      : [`${name} already tags ${existing.commit}, not ${commit}`];
  }

  // The highest same-prefix tag at or above the version, so the message names one.
  const blocking = tags
    .filter((tag) => tag.name.startsWith(`${prefix}/v`))
    .map((tag) => ({
      name: tag.name,
      version: parseVersion(tag.name.slice(prefix.length + 2)),
    }))
    .filter((tag) => tag.version && compare(tag.version, parsed) >= 0)
    .sort((a, b) => compare(b.version, a.version))[0];
  return blocking ? [`${version} is not above ${blocking.name}`] : [];
};

/** Prints each error as a GitHub annotation and exits 1 if there are any. */
export const failOn = (errors) => {
  for (const error of errors) console.log(`::error::${error}`);
  if (errors.length > 0) process.exit(1);
};
