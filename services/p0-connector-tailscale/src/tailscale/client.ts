import type { Logger } from "@p0security/connector-core";

import type { Credential, TailnetCredentials } from "../credentials.ts";
import { type ClientSecretValue, getClientSecret } from "../secrets.ts";
import {
  type TailnetCall,
  type TokenGrant,
  exchangeClientCredentials,
  exchangeIdentityToken,
} from "./api.ts";
import {
  TokenRejectedError,
  isTokenRejected,
  isUnauthorized,
  reasonOf,
} from "./errors.ts";
import {
  type IdentityTokenSource,
  federatedAudience,
} from "./identity/source.ts";
import { READ_SCOPES, WRITE_SCOPES } from "./scopes.ts";

const MINUTE_MS = 60 * 1000;

// A token is dropped five minutes before it expires, so a call never starts
// with one about to lapse. Tailscale's tokens last an hour.
const EXPIRY_MARGIN_MS = 5 * MINUTE_MS;

// How long a token is used when the response doesn't say how long it lasts.
const FALLBACK_LIFETIME_MS = 10 * MINUTE_MS;

type Token = {
  value: string;
  usableUntil: number;
  /**
   * The scopes the token carries: the ones Tailscale names, or an OAuth
   * client's asked-for ones when it names none, since Tailscale refuses to
   * issue a token without one of those. `undefined` when they aren't known.
   */
  scopes: string[] | undefined;
};

type CachedToken = {
  /** The version of the secret the token was exchanged for. */
  version: string;
  /** Pending while the exchange is in flight, so concurrent calls share it. */
  token: Promise<Token>;
};

// One per container, so a warm instance reuses a token across calls. It holds
// access tokens only, never a client secret or an identity token.
const tokenCache = new Map<string, CachedToken>();

/** Clears every cached token. For tests. */
export const resetTokenCache = () => tokenCache.clear();

// A federated token carries every scope configured on the identity, since
// the exchange takes none, so there is one per identity.
const FEDERATED_VERSION = "federated";

/**
 * One entry per credential and scope set, in a fixed order. An OAuth client's
 * key also holds the pointer, so a secret moved to another vault is a miss.
 */
const cacheKey = (credential: Credential, scopes: readonly string[]): string =>
  credential.kind === "federated"
    ? JSON.stringify([credential.kind, credential.clientId])
    : JSON.stringify([
        credential.kind,
        credential.clientId,
        credential.secret.manager,
        credential.secret.secretId,
        credential.secret.manager === "aws"
          ? credential.secret.region
          : credential.secret.projectId,
        [...scopes].sort(),
      ]);

const scopesOf = (scope: string): string[] => scope.split(" ").filter(Boolean);

/**
 * One tailnet's Tailscale API, as the connector's credential.
 *
 * Build one per call to the connector. It reads an OAuth client's secret
 * once, so a rotated secret or a pulled read grant takes effect on the next
 * call. Tokens are cached per (credential, scope set, secret version), and a
 * cached one Tailscale answers with a 401 is dropped and the call retried
 * once.
 *
 * An OAuth client's tokens are narrowed per call: {@link read} asks for
 * read-only scopes, and {@link write} for the posture write scope only. A
 * federated identity's token carries whatever the identity is configured
 * with, because Tailscale's exchange takes no scope.
 */
export const newTailscaleClient = ({
  credentials,
  log,
  identityToken,
}: {
  credentials: TailnetCredentials;
  log: Logger;
  identityToken: IdentityTokenSource;
}) => {
  const { tailnet, credential } = credentials;

  let secretRead: Promise<ClientSecretValue> | undefined;
  const readSecret = (): Promise<ClientSecretValue> =>
    credential.kind === "vault"
      ? (secretRead ??= getClientSecret(credential.secret))
      : Promise.resolve({ secret: "", version: FEDERATED_VERSION });

  const grantFor = async (
    scopes: readonly string[],
    secret: string
  ): Promise<TokenGrant> => {
    if (credential.kind === "vault") {
      return exchangeClientCredentials({
        log,
        clientId: credential.clientId,
        clientSecret: secret,
        scopes,
      });
    }
    const jwt = await identityToken(federatedAudience(credential.clientId));
    return exchangeIdentityToken({ log, clientId: credential.clientId, jwt });
  };

  /** Exchanges the credential for a token with `scopes`, uncached. */
  const mint = (scopes: readonly string[], secret: string): Promise<Token> => {
    const askedAt = Date.now();
    return grantFor(scopes, secret).then(
      ({ accessToken, scope, expiresIn }) => ({
        value: accessToken,
        usableUntil:
          expiresIn === undefined
            ? askedAt + FALLBACK_LIFETIME_MS
            : askedAt + expiresIn * 1000 - EXPIRY_MARGIN_MS,
        scopes:
          scope !== undefined
            ? scopesOf(scope)
            : credential.kind === "vault" && scopes.length > 0
              ? [...scopes]
              : undefined,
      }),
      (error: unknown) => {
        throw isTokenRejected(error)
          ? new TokenRejectedError(error.status, reasonOf(error), scopes)
          : error;
      }
    );
  };

  /** Starts an exchange, cached while it's in flight. A failed one is evicted. */
  const exchange = (
    key: string,
    scopes: readonly string[],
    { secret, version }: ClientSecretValue
  ): CachedToken => {
    const entry: CachedToken = { version, token: mint(scopes, secret) };
    tokenCache.set(key, entry);
    entry.token.catch(() => {
      if (tokenCache.get(key) === entry) tokenCache.delete(key);
    });
    return entry;
  };

  /** A usable token for `scopes`, and whether this call exchanged for it. */
  const currentToken = async (scopes: readonly string[]) => {
    const key = cacheKey(credential, scopes);
    const secret = await readSecret();
    for (;;) {
      const cached = tokenCache.get(key);
      if (cached?.version !== secret.version) {
        const entry = exchange(key, scopes, secret);
        return { key, entry, token: await entry.token, fresh: true };
      }
      const token = await cached.token;
      if (Date.now() < token.usableUntil) {
        return { key, entry: cached, token, fresh: false };
      }
      if (tokenCache.get(key) === cached) tokenCache.delete(key);
    }
  };

  /** Runs `request` with a token for `scopes`, retrying once with a new one after a 401 for a cached one. */
  const withToken = async <T>(
    scopes: readonly string[],
    request: (call: TailnetCall) => Promise<T>
  ): Promise<T> => {
    const { key, entry, token, fresh } = await currentToken(scopes);
    try {
      return await request(callWith(token));
    } catch (error) {
      // A 401 for a token this call just exchanged won't be cured by another.
      if (fresh || !isUnauthorized(error)) throw error;
      log.info("exchanging again after Tailscale refused the cached token");
      if (tokenCache.get(key) === entry) tokenCache.delete(key);
      const retry = await currentToken(scopes);
      return request(callWith(retry.token));
    }
  };

  const callWith = (token: Token): TailnetCall => ({
    log,
    tailnet,
    accessToken: token.value,
    tokenScopes: token.scopes,
  });

  return {
    tailnet,
    credentialKind: credential.kind,

    /**
     * Proves the credential can be read: an OAuth client's secret, or the
     * connector's own cloud identity token for a federated identity. Every
     * other call does this first, so a failure here says the credential is
     * the problem.
     */
    checkCredential: async (): Promise<void> => {
      if (credential.kind === "vault") {
        await readSecret();
        return;
      }
      await identityToken(federatedAudience(credential.clientId));
    },

    /**
     * Exchanges for a token with `scopes`, always, so a cached token can't
     * vouch for a credential revoked or changed since. Returns the scopes
     * Tailscale says it carries. Throws {@link TokenRejectedError} when
     * Tailscale won't exchange.
     *
     * An OAuth client's token isn't cached: it's minted only to probe, and
     * one asked for with no scope, or with `policy_file`, can carry more
     * than a read or a write needs. A federated one is, since its exchange
     * takes no scope and reads and writes use the same token.
     */
    exchangeFor: async (scopes: readonly string[]): Promise<string[]> => {
      const secret = await readSecret();
      const token =
        credential.kind === "federated"
          ? exchange(cacheKey(credential, scopes), scopes, secret).token
          : mint(scopes, secret.secret);
      return (await token).scopes ?? [];
    },

    /** Runs `request` with a read-only token. */
    read: <T>(request: (call: TailnetCall) => Promise<T>) =>
      withToken(READ_SCOPES, request),

    /** Runs `request` with the write token, which only sets device attributes. */
    write: <T>(request: (call: TailnetCall) => Promise<T>) =>
      withToken(WRITE_SCOPES, request),
  };
};

export type TailscaleClient = ReturnType<typeof newTailscaleClient>;
