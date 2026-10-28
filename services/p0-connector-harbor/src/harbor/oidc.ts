import { ConnectorError, type Logger } from "@p0security/connector-core";
import { z } from "zod";

import type { AdminCredential } from "../admin-credential.ts";
import { describeFailure, failureFacts } from "../failure.ts";
import { refusal } from "../refusals.ts";
import { HARBOR_TIMEOUT_MS, readBounded } from "./api.ts";

/**
 * The longest ID token the connector sends on. A Google ID token is about a
 * kilobyte, and one with many group claims a few. The cap keeps the length
 * check ahead of the pattern, which then runs over a bounded string.
 */
export const MAX_ID_TOKEN_LENGTH = 16_384;

// A JWS in compact form: three base64url parts. Only its form is checked:
// Harbor verifies the token. The form keeps anything that isn't a token,
// a line break included, out of the `Authorization` header.
const ID_TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * The OAuth 2.0 error codes a token endpoint answers with (RFC 6749, 5.2), the
 * only ones a message names. Anything else a provider sends isn't quoted.
 */
const OAUTH_ERRORS: ReadonlySet<string> = new Set([
  "invalid_request",
  "invalid_client",
  "invalid_grant",
  "unauthorized_client",
  "unsupported_grant_type",
  "invalid_scope",
]);

const discoveryDocument = z.object({
  issuer: z.string().max(2048),
  token_endpoint: z.string().max(2048),
  token_endpoint_auth_methods_supported: z
    .array(z.string().max(255))
    .max(100)
    .optional(),
});

// A token endpoint's answer, either way: a JSON object, whose fields are
// checked where they are read. `z.object` refuses an array and `null`.
const tokenBody = z.object({
  id_token: z.unknown().optional(),
  refresh_token: z.unknown().optional(),
  error: z.unknown().optional(),
});

/** `text` as JSON, or `undefined` when it isn't JSON. */
const jsonOf = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

/** What a token endpoint's 2xx said, as the connector reads it. */
export type TokenAnswer =
  /** An ID token in the form of one. `rotated`: a new refresh token came with it. */
  | { kind: "id_token"; idToken: string; rotated: boolean }
  /** JSON, but no ID token, or one that isn't in the form of one. */
  | { kind: "no_id_token" }
  /** Not a JSON object. */
  | { kind: "not_json" };

/**
 * Reads a token endpoint's 2xx body. Never throws, and nothing of the body
 * comes back but an ID token in the form of one.
 */
export const parseTokenAnswer = (
  text: string,
  refreshToken: string
): TokenAnswer => {
  const parsed = tokenBody.safeParse(jsonOf(text));
  if (!parsed.success) return { kind: "not_json" };
  const { id_token: idToken, refresh_token: newRefreshToken } = parsed.data;
  if (
    typeof idToken !== "string" ||
    idToken.length > MAX_ID_TOKEN_LENGTH ||
    !ID_TOKEN.test(idToken)
  ) {
    return { kind: "no_id_token" };
  }
  return {
    kind: "id_token",
    idToken,
    rotated:
      typeof newRefreshToken === "string" && newRefreshToken !== refreshToken,
  };
};

/**
 * The OAuth error code in a token endpoint's error body, when it is one of
 * {@link OAUTH_ERRORS}, and `undefined` otherwise. Never throws, and never
 * returns anything of the body but one of those codes.
 */
export const parseTokenError = (
  text: string | undefined
): string | undefined => {
  if (text === undefined) return undefined;
  const parsed = tokenBody.safeParse(jsonOf(text));
  if (!parsed.success) return undefined;
  const { error } = parsed.data;
  return typeof error === "string" && OAUTH_ERRORS.has(error)
    ? error
    : undefined;
};

/** A URL as `URL`, when it is https with no username or password. */
const httpsUrl = (value: string): URL | undefined => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" &&
      url.username === "" &&
      url.password === ""
      ? url
      : undefined;
  } catch {
    return undefined;
  }
};

type Answer = { status: number; text: string | undefined };

/**
 * Mints an ID token for the Harbor admin user from `credential`'s refresh
 * token, at the token endpoint `<issuer>/.well-known/openid-configuration`
 * names: the OAuth `refresh_token` grant on Harbor's own OIDC client, so the
 * token's audience is Harbor.
 *
 * Every call to the provider is https only, follows no redirect (a 3xx is a
 * failure), gives up after Harbor's timeout, and reads a bounded body.
 * Nothing of the credential, the token or the provider's answers goes into
 * a log line or an error: a failure says which step failed and what the
 * provider's status or OAuth error code was. `host` is the Harbor instance's,
 * for messages.
 */
export const mintIdToken = async ({
  credential: { issuer, clientId, clientSecret, refreshToken },
  host,
  logger,
}: {
  credential: AdminCredential;
  host: string;
  logger: Logger;
}): Promise<string> => {
  // The issuer parsed as an https URL when the secret was read.
  const provider = new URL(issuer).host;
  const payload = { host, provider };
  const SIGN_IN = `sign Harbor's admin account in for ${host}`;

  const exchange = async (
    step: "discovery" | "token",
    url: URL,
    init: RequestInit
  ): Promise<Answer> => {
    try {
      const response = await fetch(url, {
        ...init,
        redirect: "manual",
        signal: AbortSignal.timeout(HARBOR_TIMEOUT_MS),
      });
      return { status: response.status, text: await readBounded(response) };
    } catch (error) {
      const cause: unknown =
        error instanceof Error && error.cause !== undefined
          ? error.cause
          : error;
      const facts = failureFacts(cause);
      logger.warn(
        { step, provider, ...facts },
        "the identity provider didn't answer"
      );
      const reason =
        error instanceof Error && error.name === "TimeoutError"
          ? `no answer within ${HARBOR_TIMEOUT_MS / 1000} seconds`
          : (describeFailure(facts) ?? "the request failed");
      throw new ConnectorError({
        type: "upstream_unavailable",
        message: `The connector couldn't reach the identity provider at ${provider} to ${SIGN_IN}: ${reason}. Check the issuer in the admin credential's secret, and try again.`,
        payload: { ...payload, step },
      });
    }
  };

  const notAProvider = (status?: number) =>
    new ConnectorError({
      type: "validation_error",
      message: `${provider} didn't answer as the OpenID provider the admin credential's secret names${status === undefined ? "" : `: it answered ${status}`}. Check that the secret's issuer is the issuer Harbor's OIDC settings use.`,
      payload: {
        ...payload,
        step: "discovery",
        ...(status === undefined ? {} : { status }),
      },
    });

  // Discovery. The document is the provider's, served over https from the
  // issuer, so its token endpoint is trusted to be the provider's own.
  const discovered = await exchange(
    "discovery",
    new URL(`${issuer}/.well-known/openid-configuration`),
    { method: "GET", headers: { Accept: "application/json" } }
  );
  if (discovered.status < 200 || discovered.status >= 300) {
    throw notAProvider(discovered.status);
  }
  let document: z.infer<typeof discoveryDocument>;
  try {
    document = discoveryDocument.parse(JSON.parse(discovered.text ?? ""));
  } catch {
    throw notAProvider();
  }
  // OpenID Connect Discovery 1.0, 4.3: the document's issuer is the one it
  // was fetched for. Trailing slashes aside, which providers differ on.
  const tokenEndpoint = httpsUrl(document.token_endpoint);
  if (
    document.issuer.replace(/\/+$/, "") !== issuer ||
    tokenEndpoint === undefined
  ) {
    throw notAProvider();
  }

  // The client authenticates with HTTP basic auth unless the provider says
  // it takes only the secret in the form (RFC 6749, 2.3.1). Basic auth form
  // encodes the ID and the secret first.
  const methods = document.token_endpoint_auth_methods_supported;
  const basic =
    methods === undefined ||
    methods.includes("client_secret_basic") ||
    !methods.includes("client_secret_post");
  const form = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    ...(basic ? {} : { client_id: clientId, client_secret: clientSecret }),
  });
  const encode = (value: string) =>
    new URLSearchParams({ v: value }).toString().slice(2);
  const minted = await exchange("token", tokenEndpoint, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      ...(basic
        ? {
            Authorization: `Basic ${Buffer.from(
              `${encode(clientId)}:${encode(clientSecret)}`
            ).toString("base64")}`,
          }
        : {}),
    },
    body: form.toString(),
  });

  const { status } = minted;
  if (status >= 200 && status < 300) {
    const answer = parseTokenAnswer(minted.text ?? "", refreshToken);
    if (answer.kind === "id_token") {
      if (answer.rotated) {
        // The connector can't store the new one: it only reads the secret.
        logger.warn(
          { provider },
          "the identity provider rotated the admin account's refresh token; the stored one may stop working"
        );
      }
      return answer.idToken;
    }
    throw new ConnectorError({
      type: "validation_error",
      message: `The identity provider at ${provider} didn't return an ID token for Harbor's admin account on ${host}. The refresh token has to be granted with the openid scope: sign the admin account in again with the openid and email scopes, and store the new refresh token in its secret.`,
      payload: { ...payload, step: "token", answer: answer.kind },
    });
  }

  const code = parseTokenError(minted.text);
  logger.warn(
    { provider, status, ...(code === undefined ? {} : { code }) },
    "the identity provider refused to mint the admin account's ID token"
  );
  if (code === "invalid_grant") {
    throw refusal({
      reason: "admin_signin_expired",
      message: `The identity provider at ${provider} refused the Harbor admin account's refresh token for ${host}: it has expired or been revoked. Someone has to sign the admin account in again and store the new refresh token in its secret.`,
      payload: { ...payload, step: "token", status },
    });
  }
  if (code === "invalid_client" || code === "unauthorized_client") {
    throw new ConnectorError({
      type: "validation_error",
      message: `The identity provider at ${provider} rejected the client ID and secret in the Harbor admin credential's secret for ${host} (${code}). Check that they are Harbor's OIDC client's ID and a current secret for it.`,
      payload: { ...payload, step: "token", status, code },
    });
  }
  if (status === 429) {
    throw new ConnectorError({
      type: "rate_limited",
      message: `The identity provider at ${provider} is limiting the connector's calls: it answered 429. Try again later.`,
      payload: { ...payload, step: "token", status },
    });
  }
  if (status >= 500) {
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `The identity provider at ${provider} answered ${status} when the connector asked it to ${SIGN_IN}. Try again later.`,
      payload: { ...payload, step: "token", status },
    });
  }
  throw new ConnectorError({
    type: "validation_error",
    message: `The identity provider at ${provider} refused to ${SIGN_IN}: it answered ${status}${code === undefined ? "" : ` (${code})`}. Check the admin credential's secret.`,
    payload: {
      ...payload,
      step: "token",
      status,
      ...(code === undefined ? {} : { code }),
    },
  });
};
