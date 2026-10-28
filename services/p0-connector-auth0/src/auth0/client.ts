import type { Logger } from "@p0security/connector-core";
import { uniq, uniqBy } from "lodash-es";
import { z } from "zod";

import type { ClientSecret, TenantCredentials } from "../credentials.ts";
import { type ClientSecretValue, getClientSecret } from "../secrets.ts";
import { type TenantCall, exchangeClientCredentials } from "./api.ts";
import {
  TokenRejectedError,
  isTokenRejected,
  isUnauthorized,
  reasonOf,
} from "./errors.ts";
import {
  type Auth0User,
  type PermissionRef,
  addOrganizationMembers,
  assignMemberRoles,
  assignUserPermissions,
  assignUserRoles,
  getUser,
  getUsersByEmail,
  listMemberRoles,
  listOrganizations,
  listResourceServers,
  listRoles,
  listUserOrganizations,
  listUserPermissions,
  listUserRoles,
  removeMemberRoles,
  removeOrganizationMembers,
  removeUserPermissions,
  removeUserRoles,
} from "./management.ts";

const MINUTE_MS = 60 * 1000;

// A token is dropped five minutes before its own `exp`. The Docker Hub
// connector drops its token one minute early. An Auth0 call can take longer to
// reach the tenant, and a token lasts a day by default, so the wider margin
// costs nothing.
const EXPIRY_MARGIN_MS = 5 * MINUTE_MS;

// How long a token is used when neither its `exp` nor `expires_in` can be
// read. Auth0's shortest configurable lifetime is longer.
const FALLBACK_LIFETIME_MS = 10 * MINUTE_MS;

type Token = {
  value: string;
  usableUntil: number;
  scopes: string[];
};

type CachedToken = {
  /** The version of the secret the token was exchanged for. */
  version: string;
  /** Pending while the exchange is in flight, so concurrent calls share it. */
  token: Promise<Token>;
};

// One per container, so a warm instance reuses a token across calls. It holds
// access tokens only, never the client secret.
const tokenCache = new Map<string, CachedToken>();

/** One entry per tenant, client and pointer, in a fixed order. */
const cacheKey = (
  tenant: string,
  clientId: string,
  pointer: ClientSecret
): string =>
  JSON.stringify([
    tenant,
    clientId,
    pointer.manager,
    pointer.secretId,
    pointer.manager === "aws" ? pointer.region : pointer.projectId,
  ]);

const tokenClaims = z.object({
  exp: z.number().optional(),
  scope: z.string().optional(),
});

/** The access token's claims, if it's a JWT whose payload can be read. */
const claimsOf = (token: string): z.infer<typeof tokenClaims> => {
  try {
    const payload = Buffer.from(token.split(".")[1] ?? "", "base64url");
    const claims = tokenClaims.safeParse(JSON.parse(payload.toString("utf8")));
    return claims.success ? claims.data : {};
  } catch {
    return {};
  }
};

const scopesOf = (scope: string | undefined): string[] =>
  (scope ?? "").split(" ").filter(Boolean);

/**
 * The tenant's Management API, as the connector's machine-to-machine client.
 *
 * Build one per call to the connector. It reads the secret once, so a rotated
 * secret or a pulled read grant takes effect on the next call. The access
 * token is cached per (tenant, client, pointer, secret version), and a cached
 * one the tenant answers with a 401 is dropped and the call retried once.
 */
export const newAuth0Client = ({
  tenant,
  clientId,
  clientSecret,
  log,
}: TenantCredentials & { log: Logger }) => {
  const key = cacheKey(tenant, clientId, clientSecret);

  let secretRead: Promise<ClientSecretValue> | undefined;
  const readSecret = () => (secretRead ??= getClientSecret(clientSecret));

  /** Drops `entry`, unless a newer one has already replaced it. */
  const drop = (entry: CachedToken) => {
    if (tokenCache.get(key) === entry) tokenCache.delete(key);
  };

  /** Starts an exchange, cached while it's in flight. A failed one is evicted. */
  const exchange = ({ secret, version }: ClientSecretValue): CachedToken => {
    const askedAt = Date.now();
    const entry: CachedToken = {
      version,
      token: exchangeClientCredentials({
        log,
        tenant,
        clientId,
        clientSecret: secret,
      }).then(
        ({ accessToken, scope, expiresIn }) => {
          const claims = claimsOf(accessToken);
          const expiry =
            claims.exp !== undefined
              ? claims.exp * 1000
              : expiresIn !== undefined
                ? askedAt + expiresIn * 1000
                : undefined;
          return {
            value: accessToken,
            usableUntil:
              expiry === undefined
                ? askedAt + FALLBACK_LIFETIME_MS
                : expiry - EXPIRY_MARGIN_MS,
            // The token's own claim, which is what the API checks.
            scopes: scopesOf(claims.scope ?? scope),
          };
        },
        (error: unknown) => {
          throw isTokenRejected(error)
            ? new TokenRejectedError(error.status, reasonOf(error))
            : error;
        }
      ),
    };
    tokenCache.set(key, entry);
    entry.token.catch(() => drop(entry));
    return entry;
  };

  /** A usable token for the secret's current version, and whether this call exchanged for it. */
  const currentToken = async (secret: ClientSecretValue) => {
    for (;;) {
      const cached = tokenCache.get(key);
      if (cached?.version !== secret.version) {
        const entry = exchange(secret);
        return { entry, token: await entry.token, fresh: true };
      }
      const token = await cached.token;
      if (Date.now() < token.usableUntil) {
        return { entry: cached, token, fresh: false };
      }
      drop(cached);
    }
  };

  /** Runs `request` with a usable access token, retrying once with a new one after a 401 for a cached one. */
  const withToken = async <T>(
    request: (call: TenantCall) => Promise<T>
  ): Promise<T> => {
    const secret = await readSecret();
    const { entry, token, fresh } = await currentToken(secret);
    try {
      return await request({ log, tenant, accessToken: token.value });
    } catch (error) {
      // A 401 for a token this call just exchanged won't be cured by another.
      if (fresh || !isUnauthorized(error)) throw error;
      log.info("exchanging again after Auth0 refused the cached access token");
      drop(entry);
      const retry = await currentToken(secret);
      return request({ log, tenant, accessToken: retry.token.value });
    }
  };

  return {
    /** Reads the client secret, which every other call does first, so a failure here says the secret is the problem. */
    readSecret: async (): Promise<void> => {
      await readSecret();
    },

    /**
     * The scopes a freshly exchanged token carries. Always exchanges, so a
     * cached token can't vouch for credentials revoked or a grant changed
     * since. Throws {@link TokenRejectedError} when the tenant won't exchange.
     */
    exchangeForScopes: async (): Promise<string[]> =>
      (await exchange(await readSecret()).token).scopes,

    withToken,

    /**
     * Every user whose email is `email`, as given or lower-cased, one per
     * unlinked identity. `/users-by-email` is case-sensitive, and Auth0
     * lower-cases only its own database users' emails.
     */
    findUsersByEmail: async (email: string): Promise<Auth0User[]> => {
      const spellings = uniq([email, email.toLowerCase()]);
      const found: Auth0User[] = [];
      for (const spelling of spellings) {
        found.push(
          ...(await withToken((call) => getUsersByEmail(call, spelling)))
        );
      }
      return uniqBy(found, ({ userId }) => userId);
    },

    getUser: (userId: string) => withToken((call) => getUser(call, userId)),

    listRoles: () => withToken(listRoles),

    listResourceServers: () => withToken(listResourceServers),

    listOrganizations: () => withToken(listOrganizations),

    listUserRoles: (userId: string) =>
      withToken((call) => listUserRoles(call, userId)),

    listUserPermissions: (userId: string, resourceServerIdentifier: string) =>
      withToken((call) =>
        listUserPermissions(call, userId, resourceServerIdentifier)
      ),

    listUserOrganizations: (userId: string) =>
      withToken((call) => listUserOrganizations(call, userId)),

    listMemberRoles: (organizationId: string, userId: string) =>
      withToken((call) => listMemberRoles(call, organizationId, userId)),

    assignUserRole: async (userId: string, roleId: string): Promise<void> => {
      await withToken((call) => assignUserRoles(call, userId, [roleId]));
    },

    removeUserRole: async (userId: string, roleId: string): Promise<void> => {
      await withToken((call) => removeUserRoles(call, userId, [roleId]));
    },

    assignUserPermission: async (
      userId: string,
      permission: PermissionRef
    ): Promise<void> => {
      await withToken((call) =>
        assignUserPermissions(call, userId, [permission])
      );
    },

    removeUserPermission: async (
      userId: string,
      permission: PermissionRef
    ): Promise<void> => {
      await withToken((call) =>
        removeUserPermissions(call, userId, [permission])
      );
    },

    addMember: async (
      organizationId: string,
      userId: string
    ): Promise<void> => {
      await withToken((call) =>
        addOrganizationMembers(call, organizationId, [userId])
      );
    },

    removeMember: async (
      organizationId: string,
      userId: string
    ): Promise<void> => {
      await withToken((call) =>
        removeOrganizationMembers(call, organizationId, [userId])
      );
    },

    assignMemberRole: async (
      organizationId: string,
      userId: string,
      roleId: string
    ): Promise<void> => {
      await withToken((call) =>
        assignMemberRoles(call, organizationId, userId, [roleId])
      );
    },

    removeMemberRole: async (
      organizationId: string,
      userId: string,
      roleId: string
    ): Promise<void> => {
      await withToken((call) =>
        removeMemberRoles(call, organizationId, userId, [roleId])
      );
    },
  };
};

export type Auth0Client = ReturnType<typeof newAuth0Client>;
