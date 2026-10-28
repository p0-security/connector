import { LambdaClient } from "@aws-sdk/client-lambda";
import {
  newAwsLambdaCloudFunctionTestClient,
  newCloudFunctionLink,
} from "@p0security/connector-core";
import { type TRPCLink, httpLink } from "@trpc/client";
import type { AnyRouter } from "@trpc/server";
import { GoogleAuth } from "google-auth-library";

/**
 * Cache for Google Cloud identity tokens, keyed by endpoint.
 */
const gcloudCache = {
  auth: undefined as GoogleAuth | undefined,
  idTokens: new Map<string, Promise<string>>(),

  /**
   * The Cloud Run service authorizes callers with a Google-signed identity token
   * whose audience is the service URL. Fetch one lazily and reuse it across
   * requests (tokens are valid for ~1h, longer than any CLI invocation).
   */
  fetchIdToken(endpoint: string): Promise<string> {
    let token = this.idTokens.get(endpoint);
    if (token) return token;

    this.auth ??= new GoogleAuth();
    token = this.auth
      .getIdTokenClient(endpoint)
      .then((client) => client.idTokenProvider.fetchIdToken(endpoint));
    this.idTokens.set(endpoint, token);
    return token;
  },
};

/**
 * Some CSPs (i.e. Cloud Run) serve an HTML error page (not JSON) when a request
 * is rejected - most commonly an auth failure. tRPC chokes trying to parse HTML
 * as JSON, surfacing cryptic "unexpected token '<'" errors. Detect a non-JSON
 * response up front and throw the actual status code instead.
 */
const jsonFetch: typeof fetch = async (input, init) => {
  const response = await fetch(input, init);
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    const body = await response.text();
    throw new Error(
      `Connector request failed with ${response.status} ${response.statusText} ` +
        `(expected JSON, got ${contentType || "no content-type"}). ` +
        `This is usually an authentication problem — verify the caller has ` +
        `privileges to call the connector.\n${body.slice(0, 500)}`
    );
  }
  return response;
};

/**
 * Reaches the connector as a GCP Cloud Run service over HTTP, gated by a
 * Google-signed identity token.
 */
export const newCloudRunLink = (endpoint: string): TRPCLink<AnyRouter> =>
  httpLink({
    url: `${endpoint}/trpc`,
    fetch: jsonFetch,
    headers: async () => ({
      authorization: `Bearer ${await gcloudCache.fetchIdToken(endpoint)}`,
    }),
  });

/**
 * Reaches the connector as an AWS Lambda function, invoked directly via the SDK.
 */
export const newLambdaLink = (lambdaArn: string): TRPCLink<AnyRouter> =>
  newCloudFunctionLink(
    newAwsLambdaCloudFunctionTestClient({
      funcName: lambdaArn,
      client: new LambdaClient(),
    })
  );
