import { newCustomAppLambdaHandler } from "@p0security/connector-sdk";

import packageJson from "../package.json" with { type: "json" };
import { newActions } from "./actions.ts";

/**
 * AWS Lambda invokes this by name (`dist/index.handler`, per this example's
 * README). P0 calls it directly via `lambda:InvokeFunction` — there is no
 * HTTP server or port to bind, unlike the Cloud Run variant of this example.
 */
export const handler = newCustomAppLambdaHandler({
  actions: newActions,
  connectorVersion: packageJson.version,
});
