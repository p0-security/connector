import {
  GetWebIdentityTokenCommand,
  STSClient,
  STSServiceException,
} from "@aws-sdk/client-sts";
import { ConnectorError, createLogger } from "@p0security/connector-core";
import { z } from "zod";

import {
  API_TIMEOUT_MS,
  databricksRequest,
  failedRequest,
  memoizeByKey,
  parse,
} from "./api.ts";
import {
  type DatabricksAccountContext,
  accountsUrl,
  cacheKey,
} from "./context.ts";

const logger = createLogger();

/**
 * The `aud` claim of the AWS token. Every federation policy P0's terraform
 * creates expects it. A policy created without `audiences` expects the
 * Databricks account ID instead, and the exchange then fails.
 */
export const DATABRICKS_TOKEN_AUDIENCE = "databricks";

/** AWS offers RS256 and ES384; Databricks verifies either against the issuer's JWKS. */
const SIGNING_ALGORITHM = "RS256";

/**
 * How long the AWS token lives. The Databricks token it's exchanged for
 * inherits this lifetime, so it also sets how long the cache below can serve
 * one token. The shortest lifetime STS allows (60 seconds) would leave nothing
 * to cache once the refresh margin is taken off, and every call would mint and
 * exchange a new token. 15 minutes keeps an intercepted token's useful window
 * short while letting a burst of calls share one exchange.
 */
export const AWS_TOKEN_LIFETIME_SECONDS = 900;

/** Refresh a cached Databricks token this long before it expires, so it never expires mid-call. */
const EXPIRY_MARGIN_MS = 60_000;

const TOKEN_EXCHANGE_GRANT_TYPE =
  "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
const DATABRICKS_SCOPE = "all-apis";

const tokenResponse = z.object({
  access_token: z.string().min(1),
  expires_in: z.number().positive(),
});

type CachedToken = { accessToken: string; expiresAt: number };

// One STS client per Lambda instance. With a region set (the Lambda runtime
// sets AWS_REGION), the v3 SDK calls the regional STS endpoint, never the
// global one, so the outbound identity token is issued in the Lambda's region.
let stsClient: STSClient | undefined;
const sts = () =>
  (stsClient ??= new STSClient({
    region: process.env.AWS_REGION,
    useGlobalEndpoint: false,
  }));

/**
 * Databricks tokens, keyed by the account and service principal they were
 * minted for. In-flight exchanges are cached too, so concurrent calls for one
 * account share a single exchange.
 */
const tokenCache = new Map<string, Promise<CachedToken>>();

/** Clears every cached token. For tests. */
export const resetTokenCache = () => tokenCache.clear();

/**
 * STS errors that mean the customer's AWS setup doesn't allow the connector to
 * mint a token: outbound identity federation isn't enabled for the account, or
 * the role may not call `sts:GetWebIdentityToken`. Any other STS failure
 * (throttling, a server fault, a timeout) is STS being unavailable, and must
 * not tell the customer their install is broken.
 */
const STS_SETUP_ERRORS = new Set([
  "OutboundWebIdentityFederationDisabledException",
  "AccessDenied",
]);

/**
 * Mints an AWS outbound identity token for the Lambda's own role
 * (`sts:GetWebIdentityToken`). This is the only credential the connector
 * holds, and it comes from the execution role, never a stored secret.
 */
const mintAwsWebIdentityToken = async (requestId: string): Promise<string> => {
  let token: string | undefined;
  try {
    const response = await sts().send(
      new GetWebIdentityTokenCommand({
        Audience: [DATABRICKS_TOKEN_AUDIENCE],
        SigningAlgorithm: SIGNING_ALGORITHM,
        DurationSeconds: AWS_TOKEN_LIFETIME_SECONDS,
      }),
      // The SDK sets no request timeout of its own, and a hung call would sit
      // in the token cache, where every caller for the account waits on it.
      { abortSignal: AbortSignal.timeout(API_TIMEOUT_MS) }
    );
    token = response.WebIdentityToken;
  } catch (error) {
    const name = error instanceof Error ? error.name : "UnknownError";
    logger.error(
      { requestId, error },
      "failed to mint AWS outbound identity token"
    );
    if (error instanceof STSServiceException && STS_SETUP_ERRORS.has(name)) {
      throw new ConnectorError({
        type: "insufficient_privileges",
        message: `Could not mint an AWS outbound identity token (${name}). Check that outbound identity federation is enabled for the AWS account and that the connector's role may call sts:GetWebIdentityToken.`,
        payload: { requestId, error: name },
      });
    }
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `Could not mint an AWS outbound identity token: AWS STS is unavailable (${name})`,
      payload: { requestId, error: name },
    });
  }

  if (!token) {
    logger.error({ requestId }, "STS returned no web identity token");
    throw new ConnectorError({
      type: "unknown",
      message: "AWS STS returned no outbound identity token",
      payload: { requestId },
    });
  }
  return token;
};

/**
 * Exchanges an AWS web identity token for a Databricks token for the service
 * principal `applicationId` (RFC 8693 token exchange, against the principal's
 * federation policy).
 *
 * The token endpoint answers a federation policy that doesn't trust this role
 * or expects another audience, or an unknown principal, with a 400 or 401.
 * Either is an install problem the customer has to fix, not a retryable
 * failure, so it fails as `insufficient_privileges` and says what to check.
 */
const exchangeForDatabricksToken = async ({
  context,
  origin,
  subjectToken,
}: {
  context: DatabricksAccountContext;
  /** The account console, already checked by the `accountsUrl` parser. */
  origin: string;
  /** The AWS web identity token. */
  subjectToken: string;
}): Promise<CachedToken> => {
  const { accountId, applicationId, requestId } = context;
  const requestedAt = Date.now();
  let response: unknown;
  try {
    response = await databricksRequest({
      origin,
      method: "POST",
      path: `/oidc/accounts/${encodeURIComponent(accountId)}/v1/token`,
      requestId,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: subjectToken,
        subject_token_type: JWT_TOKEN_TYPE,
        client_id: applicationId,
        scope: DATABRICKS_SCOPE,
      }).toString(),
    });
  } catch (error) {
    const status = failedRequest(error)?.status;
    if (
      !(error instanceof ConnectorError) ||
      (status !== 400 && status !== 401)
    ) {
      throw error;
    }
    throw new ConnectorError({
      type: "insufficient_privileges",
      message: `${error.message}. Check that the federation policy of service principal ${applicationId} trusts the connector's AWS role and expects the audience "${DATABRICKS_TOKEN_AUDIENCE}".`,
      payload: error.data.payload,
      cause: error,
    });
  }

  const { access_token, expires_in } = parse({
    schema: tokenResponse,
    data: response,
    what: "token endpoint",
    requestId,
  });
  return {
    accessToken: access_token,
    expiresAt: requestedAt + expires_in * 1000,
  };
};

const freshToken = async (
  context: DatabricksAccountContext
): Promise<CachedToken> => {
  // Re-parsed here so the AWS token can never go to a host that isn't a
  // Databricks account console, even if a caller skipped the context parser.
  const origin = accountsUrl.safeParse(context.accountsUrl);
  if (!origin.success) {
    throw new ConnectorError({
      type: "validation_error",
      message: "Accounts URL must be a Databricks account console",
      payload: { requestId: context.requestId },
    });
  }
  const subjectToken = await mintAwsWebIdentityToken(context.requestId);
  const token = await exchangeForDatabricksToken({
    context,
    origin: origin.data,
    subjectToken,
  });
  logger.info(
    {
      requestId: context.requestId,
      accountId: context.accountId,
      applicationId: context.applicationId,
      expiresAt: new Date(token.expiresAt).toISOString(),
    },
    "exchanged AWS identity for a Databricks token"
  );
  return token;
};

/**
 * Returns a Databricks access token for the service principal named in
 * `context`, from the cache while it has more than {@link EXPIRY_MARGIN_MS}
 * left, otherwise by minting and exchanging a new AWS identity token.
 */
export const databricksAccessToken = async (
  context: DatabricksAccountContext
): Promise<string> => {
  const key = cacheKey(context);
  const cached = tokenCache.get(key);
  if (cached) {
    // A failed exchange is never served from the cache: it reads as a miss.
    const token = await cached.catch(() => undefined);
    if (token && token.expiresAt - EXPIRY_MARGIN_MS > Date.now()) {
      return token.accessToken;
    }
    // Evict only the entry read above, not one a concurrent call put there since.
    if (tokenCache.get(key) === cached) tokenCache.delete(key);
  }

  const token = await memoizeByKey(tokenCache, key, () => freshToken(context));
  return token.accessToken;
};
