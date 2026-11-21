// Fails unless VERSION can be released: a plain x.y.z, its v tag free, above
// every v* tag on origin (connector-core and connector-sdk share that
// namespace with their v0.* NPM tags), and above the version main's services
// already report. Run from a checkout of main.
import { execFileSync } from "node:child_process";

import {
  failOn,
  readServiceVersions,
  releaseVersionErrors,
} from "./release-version.mjs";

const version = process.env.VERSION ?? "";

// From origin, not the local clone, so a tag pushed since the checkout counts.
const tags = execFileSync(
  "git",
  ["ls-remote", "--tags", "--refs", "origin", "refs/tags/v*"],
  { encoding: "utf8" }
)
  .split("\n")
  .filter(Boolean)
  .map((line) => line.split("\t")[1].replace(/^refs\/tags\//, ""));

const current = readServiceVersions().map((entry) => entry.version);

failOn(releaseVersionErrors(version, tags, current));
console.log(`${version} can be released.`);
