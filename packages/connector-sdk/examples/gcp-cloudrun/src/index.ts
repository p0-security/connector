import { newCustomAppCloudRunServer } from "@p0security/connector-sdk";

import packageJson from "../package.json" with { type: "json" };
import { newActions } from "./actions.ts";

/**
 * Fail at startup rather than on P0's first call.
 *
 * The SDK's Cloud Run server admits a request only if it carries a
 * Google-signed ID token whose `email` claim matches `INVOKER_SA_EMAIL`. With
 * the variable unset it fails closed on every request — including P0's
 * install-time reachability check — as an indistinguishable 403. Crashing here
 * instead puts the reason in the Cloud Run revision logs, where you look first.
 */
const invokerServiceAccount = process.env.INVOKER_SA_EMAIL;
if (!invokerServiceAccount) {
  throw new Error(
    "INVOKER_SA_EMAIL is unset. Set it to the service account P0 impersonates " +
      "to call this connector, and grant that account roles/run.invoker on " +
      "this service."
  );
}

const run = newCustomAppCloudRunServer({
  actions: newActions,
  connectorVersion: packageJson.version,
});

// Binds an Express server on $PORT (Cloud Run sets this; the SDK defaults to
// 8080) serving the connector's tRPC router under /trpc.
run();
