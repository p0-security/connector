import {
  GetWebIdentityTokenCommand,
  STSClient,
  STSServiceException,
} from "@aws-sdk/client-sts";
import { ConnectorError } from "@p0security/connector-core";

import { API_TIMEOUT_MS } from "../api.ts";
import type { IdentityTokenSource } from "./source.ts";

/**
 * How long the AWS token lives. Tailscale's own IAM sample for federation
 * caps `sts:DurationSeconds` at 300, and its own client asks for 300, so a
 * role policy copied from Tailscale's docs allows this and nothing longer.
 * The token is exchanged at once, so a short life costs nothing.
 */
export const AWS_TOKEN_LIFETIME_SECONDS = 300;

/** What Tailscale's own client signs with. */
const SIGNING_ALGORITHM = "ES384";

// One STS client per Lambda instance. With a region set (the Lambda runtime
// sets AWS_REGION), the v3 SDK calls the regional STS endpoint, never the
// global one, which doesn't serve `GetWebIdentityToken`.
let stsClient: STSClient | undefined;
const sts = () =>
  (stsClient ??= new STSClient({
    region: process.env.AWS_REGION,
    useGlobalEndpoint: false,
  }));

/**
 * STS errors that mean the customer's AWS setup doesn't let the connector
 * mint a token: outbound identity federation isn't enabled for the account,
 * or the role may not call `sts:GetWebIdentityToken` for this audience and
 * duration. Any other STS failure (throttling, a server fault, a timeout) is
 * STS being unavailable, and must not tell the customer their install is
 * broken.
 */
const STS_SETUP_ERRORS = new Set([
  "OutboundWebIdentityFederationDisabledException",
  "AccessDenied",
]);

/** Asks STS for the token, mapping its failures. */
const mint = async (audience: string): Promise<string | undefined> => {
  try {
    const response = await sts().send(
      new GetWebIdentityTokenCommand({
        Audience: [audience],
        SigningAlgorithm: SIGNING_ALGORITHM,
        DurationSeconds: AWS_TOKEN_LIFETIME_SECONDS,
      }),
      // The SDK sets no request timeout of its own, and a hung call would sit
      // in the token cache, where every caller for the credential waits on it.
      { abortSignal: AbortSignal.timeout(API_TIMEOUT_MS) }
    );
    return response.WebIdentityToken;
  } catch (error) {
    const name = error instanceof Error ? error.name : "UnknownError";
    if (error instanceof STSServiceException && STS_SETUP_ERRORS.has(name)) {
      throw new ConnectorError({
        type: "insufficient_privileges",
        message: `The connector couldn't mint an AWS outbound identity token (${name}). Check that outbound identity federation is enabled for the AWS account, and that the connector's role may call sts:GetWebIdentityToken for the audience ${audience} with a duration of ${AWS_TOKEN_LIFETIME_SECONDS} seconds.`,
        payload: { error: name },
      });
    }
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `The connector couldn't mint an AWS outbound identity token: AWS STS is unavailable (${name}).`,
      payload: { error: name },
    });
  }
};
/**
 * Mints an AWS outbound identity token for the Lambda's own role
 * (`sts:GetWebIdentityToken`). It comes from the execution role, never a
 * stored secret. Copied from the Databricks connector's `federation.ts`.
 */
export const awsIdentityToken: IdentityTokenSource = async (audience) => {
  const token = await mint(audience);
  if (!token) {
    throw new ConnectorError({
      type: "unknown",
      message: "AWS STS returned no outbound identity token.",
      payload: {},
    });
  }
  return token;
};
