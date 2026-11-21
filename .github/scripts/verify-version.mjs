// Fails unless every services/*/package.json is at VERSION, a plain x.y.z.
import {
  failOn,
  readServiceVersions,
  serviceVersionErrors,
} from "./release-version.mjs";

const version = process.env.VERSION ?? "";
failOn(serviceVersionErrors(version));
console.log(`All ${readServiceVersions().length} services are at ${version}.`);
