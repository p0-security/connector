import { requireAllowedDomains } from "./allowed-domains.ts";

// Without a usable `DOMAIN_ALLOW_PATTERN` the connector refuses to start,
// and says which variable is wrong.
//
// TODO(INT-369): go back to static imports once `newMemberVerifier` in
// `packages/gcloud/src/member-verify.ts` compiles the pattern itself. Today
// that module compiles it as it loads, and the framework imports it, so a
// pattern that doesn't compile would fail there first with a bare
// `SyntaxError`. Importing the rest dynamically lets this check run first.
requireAllowedDomains();

const { createLogger, newCloudFunction } =
  await import("@p0security/connector");
const { connectorRouter } = await import("./router.ts");

const logger = createLogger();
export const handler = newCloudFunction(connectorRouter, async () => ({
  logger,
}));
