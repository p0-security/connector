// Fails unless each tag prefix's package.json files all hold one version.
// Run on every PR, so a release never finds them disagreeing.
import {
  TAG_PREFIXES,
  consistencyErrors,
  failOn,
  readVersions,
} from "./release-version.mjs";

const prefixes = Object.keys(TAG_PREFIXES);
failOn(prefixes.flatMap((prefix) => consistencyErrors(prefix)));
for (const prefix of prefixes) {
  const versions = readVersions(prefix);
  console.log(
    `${versions.length} ${prefix} package.json files are at ${versions[0]?.version}.`
  );
}
