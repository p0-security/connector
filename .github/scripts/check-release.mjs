// Fails unless TAG_PREFIX/vVERSION can be released from COMMIT: a known tag
// prefix, every package.json for it at VERSION in the checkout at ROOT, and
// a tag that is free (or already on COMMIT) and above every earlier tag with
// the same prefix.
import { execFileSync } from "node:child_process";

import {
  failOn,
  parseTags,
  tagErrors,
  tagPrefixErrors,
  versionErrors,
} from "./release-version.mjs";

const { TAG_PREFIX = "", VERSION = "", COMMIT = "", ROOT = "." } = process.env;

failOn(tagPrefixErrors(TAG_PREFIX));

// From origin, not the local clone, so a tag pushed since the checkout counts.
const tags = parseTags(
  execFileSync("git", ["ls-remote", "--tags", "origin"], { encoding: "utf8" })
);

failOn([
  ...tagErrors(TAG_PREFIX, VERSION, COMMIT, tags),
  ...versionErrors(TAG_PREFIX, VERSION, ROOT),
]);
console.log(`${TAG_PREFIX}/v${VERSION} can be released from ${COMMIT}.`);
