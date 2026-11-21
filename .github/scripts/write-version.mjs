// Writes VERSION into every services/*/package.json, then reads them all back.
// Refuses to lower any service's version.
// The root package.json stays at 0.0.0 and packages/* are left alone: they
// are versioned separately, connector-core and connector-sdk on NPM.
import {
  downgradeErrors,
  failOn,
  parseVersion,
  serviceVersionErrors,
  writeServiceVersions,
} from "./release-version.mjs";

const version = process.env.VERSION ?? "";
if (!parseVersion(version)) {
  failOn([`version must be a plain x.y.z (got "${version}")`]);
}

failOn(downgradeErrors(version));

const paths = writeServiceVersions(version);
failOn(serviceVersionErrors(version));
console.log(`Wrote ${version} to ${paths.length} services.`);
