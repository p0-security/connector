import type { Logger } from "@p0security/connector-core";
import { z } from "zod";

import type {
  CoreRole,
  OrgCredentials,
  TokenSecret,
} from "../accesses/role/definition.ts";
import { type OrgAccessToken, getOrgAccessToken } from "../secrets.ts";
import {
  type InviteResult,
  type NewInvite,
  type OrgCall,
  type OrgInvite,
  type OrgMember,
  PAGE_SIZE,
  deleteInvite,
  deleteMember,
  exchangeToken,
  listInvites,
  listMembers,
  postDryRunInvite,
  postInvite,
  putMemberRole,
} from "./api.ts";
import {
  TokenRejectedError,
  isTokenRejected,
  isUnauthorized,
} from "./errors.ts";

const MINUTE_MS = 60 * 1000;

// A JWT is dropped a minute before its own `exp`, which covers clock skew and
// a call that starts just before the cutoff.
const EXPIRY_MARGIN_MS = MINUTE_MS;

// How long a JWT without a readable `exp` is used. Docker Hub's last 15 minutes.
const FALLBACK_LIFETIME_MS = 14 * MINUTE_MS;

type Jwt = { value: string; usableUntil: number };

type CachedJwt = {
  /** The version of the secret the JWT was exchanged for. */
  version: string;
  /** Pending while the exchange is in flight, so concurrent calls share it. */
  jwt: Promise<Jwt>;
};

// One per container, so a warm instance reuses a JWT across calls. It holds
// JWTs only, never the token.
const jwtCache = new Map<string, CachedJwt>();

/** One entry per org and pointer, in a fixed order. A JWT is for one org. */
const cacheKey = (org: string, tokenSecret: TokenSecret): string =>
  JSON.stringify([
    org,
    tokenSecret.manager,
    tokenSecret.secretId,
    tokenSecret.manager === "aws" ? tokenSecret.region : tokenSecret.projectId,
  ]);

const jwtClaims = z.object({ exp: z.number() });

/** The JWT's own `exp`, in milliseconds, if it has one that can be read. */
const expiryOf = (jwt: string): number | undefined => {
  try {
    const payload = Buffer.from(jwt.split(".")[1] ?? "", "base64url");
    const claims = jwtClaims.safeParse(JSON.parse(payload.toString("utf8")));
    return claims.success ? claims.data.exp * 1000 : undefined;
  } catch {
    return undefined;
  }
};

/**
 * Docker Hub, as one organization's access token.
 *
 * Build one per call to the connector. It reads the secret once, so a rotated
 * secret or a pulled read grant takes effect on the next call. The JWT is
 * cached per (org, pointer, secret version), and a cached one that Docker
 * Hub answers with a 401 is dropped and the call retried once.
 */
export const newDockerHubClient = ({
  org,
  tokenSecret,
  log,
}: OrgCredentials & { log: Logger }) => {
  const key = cacheKey(org, tokenSecret);

  let secretRead: Promise<OrgAccessToken> | undefined;
  const readSecret = () => (secretRead ??= getOrgAccessToken(tokenSecret));

  /** Drops `entry`, unless a newer one has already replaced it. */
  const drop = (entry: CachedJwt) => {
    if (jwtCache.get(key) === entry) jwtCache.delete(key);
  };

  /** Starts an exchange, cached while it's in flight. A failed one is evicted. */
  const exchange = ({ token, version }: OrgAccessToken): CachedJwt => {
    const askedAt = Date.now();
    const entry: CachedJwt = {
      version,
      jwt: exchangeToken({ log, org, token }).then(
        (value) => {
          const expiry = expiryOf(value);
          return {
            value,
            usableUntil:
              expiry === undefined
                ? askedAt + FALLBACK_LIFETIME_MS
                : expiry - EXPIRY_MARGIN_MS,
          };
        },
        (error: unknown) => {
          throw isTokenRejected(error)
            ? new TokenRejectedError(error.status)
            : error;
        }
      ),
    };
    jwtCache.set(key, entry);
    entry.jwt.catch(() => drop(entry));
    return entry;
  };

  /** A usable JWT for the secret's current version, and whether this call exchanged for it. */
  const currentJwt = async (secret: OrgAccessToken) => {
    for (;;) {
      const cached = jwtCache.get(key);
      if (cached?.version !== secret.version) {
        const entry = exchange(secret);
        return { entry, jwt: (await entry.jwt).value, fresh: true };
      }
      const { value, usableUntil } = await cached.jwt;
      if (Date.now() < usableUntil) {
        return { entry: cached, jwt: value, fresh: false };
      }
      drop(cached);
    }
  };

  const withJwt = async <T>(
    request: (call: OrgCall) => Promise<T>
  ): Promise<T> => {
    const secret = await readSecret();
    const { entry, jwt, fresh } = await currentJwt(secret);
    try {
      return await request({ log, jwt, org });
    } catch (error) {
      // A 401 for a JWT this call just exchanged won't be cured by another.
      if (fresh || !isUnauthorized(error)) throw error;
      log.info("Docker Hub refused the cached JWT; exchanging the token again");
      drop(entry);
      return request({ log, jwt: (await currentJwt(secret)).jwt, org });
    }
  };

  /** Every member `search` finds who also passes `matches`, page by page. */
  const searchMembers = async (
    search: string,
    matches: (member: OrgMember) => boolean
  ): Promise<OrgMember[]> => {
    const found: OrgMember[] = [];
    for (let page = 1; ; page++) {
      const { members, hasNext } = await withJwt((call) =>
        listMembers({ ...call, search, page, pageSize: PAGE_SIZE })
      );
      found.push(...members.filter(matches));
      if (!hasNext || members.length === 0) return found;
    }
  };

  return {
    /**
     * Whether Docker Hub exchanges the token now. Always exchanges, so a
     * cached JWT can't vouch for a token revoked since.
     */
    isTokenAccepted: async (): Promise<boolean> => {
      try {
        await exchange(await readSecret()).jwt;
        return true;
      } catch (error) {
        if (error instanceof TokenRejectedError) return false;
        throw error;
      }
    },

    /** Reads one member, to see that the token may. */
    readOneMember: async (): Promise<void> => {
      await withJwt((call) => listMembers({ ...call, page: 1, pageSize: 1 }));
    },

    /** Has Docker Hub validate an invite without sending it or using a seat. */
    dryRunInvite: (invite: NewInvite): Promise<void> =>
      withJwt((call) => postDryRunInvite({ ...call, ...invite })),

    /** Every org member whose email is `email`, ignoring case. Pending invitees aren't members. */
    findMembersByEmail: (email: string): Promise<OrgMember[]> => {
      const wanted = email.toLowerCase();
      return searchMembers(
        email,
        (member) => member.email?.toLowerCase() === wanted
      );
    },

    /** The org member with `username`, or `null` when there's none. */
    findMemberByUsername: async (
      username: string
    ): Promise<OrgMember | null> => {
      const wanted = username.toLowerCase();
      const [match] = await searchMembers(
        username,
        (member) => member.username.toLowerCase() === wanted
      );
      return match ?? null;
    },

    /** The org's pending invites to `email`, matched ignoring case. */
    findInvites: async (email: string): Promise<OrgInvite[]> => {
      const wanted = email.toLowerCase();
      const invites = await withJwt(listInvites);
      return invites.filter(({ invitee }) => invitee.toLowerCase() === wanted);
    },

    setRole: (member: { username: string; role: CoreRole }): Promise<void> =>
      withJwt((call) => putMemberRole({ ...call, ...member })),

    removeMember: (username: string): Promise<void> =>
      withJwt((call) => deleteMember({ ...call, username })),

    /** Invites `email` with `role`, and says what Docker Hub did with it. */
    invite: (invite: NewInvite): Promise<InviteResult> =>
      withJwt((call) => postInvite({ ...call, ...invite })),

    cancelInvite: (id: string): Promise<void> =>
      withJwt((call) => deleteInvite({ ...call, id })),
  };
};

export type DockerHubClient = ReturnType<typeof newDockerHubClient>;
