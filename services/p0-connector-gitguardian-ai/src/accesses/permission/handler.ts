import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector-core";
import {
  SecretNotFoundError,
  type SecretRef,
} from "@p0security/connector-secret-manager-client";
import { createHash } from "node:crypto";

import {
  type ApiToken,
  type GitguardianAuth,
  deleteToken,
  getCurrentToken,
  listActiveTokens,
  mintToken,
} from "../../gitguardian/gitguardian-api.ts";
import { createSecretManager, getAdminToken } from "../../secrets.ts";
import { sleep } from "../../sleep.ts";
import { requestableScopes, spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type RequestContext = ResourceSchema["RequestContext"];
type WorkspaceContext = ResourceSchema["ListerQuery"]["context"];

const DAY_MS = 24 * 60 * 60 * 1000;
/** GitGuardian requires a lifetime, so a grant with no end gets this. */
const NO_END_LIFETIME_DAYS = 365;
/** Waits before each retry of a 409, a rate limit or an outage. */
const RETRY_DELAYS_MS = [2_000, 4_000, 8_000];

const secretRef = (userId: string) => userId as SecretRef;

/** Every token of one grant is named with this prefix, then the time it was
 * minted, so that the old and new tokens of a change have unique names. */
const tokenPrefixFor = (userId: ResourceSchema["UserId"]) =>
  `P0 ${createHash("sha256").update(userId).digest("hex").slice(0, 16)} `;

/** Whole days until `grantEndsAt`, rounded up, minimum 1. */
const lifetimeDays = (grantEndsAt: string | null, now = Date.now()) =>
  grantEndsAt === null
    ? NO_END_LIFETIME_DAYS
    : Math.max(1, Math.ceil((Date.parse(grantEndsAt) - now) / DAY_MS));

const errorStatus = (error: unknown) =>
  error instanceof ConnectorError ? error.data.payload?.status : undefined;

const errorDetail = (error: unknown) =>
  error instanceof ConnectorError ? error.data.payload?.detail : undefined;

const isRetryable = (error: unknown) =>
  error instanceof ConnectorError &&
  (error.data.type === "upstream_unavailable" ||
    error.data.type === "rate_limited");

/** Runs `call`, waiting and retrying while `retry` says so. */
const withRetries = async <T>(
  call: () => Promise<T>,
  retry: (error: unknown) => boolean
): Promise<T> => {
  for (const delay of RETRY_DELAYS_MS) {
    try {
      return await call();
    } catch (error) {
      if (!retry(error)) throw error;
      await sleep(delay);
    }
  }
  return await call();
};

const refusal = (message: string, payload: Record<string, string> = {}) =>
  new ConnectorError({ type: "validation_error", message, payload });

/** The admin token, its own record, and the secret manager. */
const newWorkspaceClients = async (context: WorkspaceContext) => {
  const secretManager = await createSecretManager(context.secrets);
  const token = await getAdminToken(
    secretManager,
    secretRef(context.secrets.adminTokenSecretId)
  );
  const auth: GitguardianAuth = { region: context.region, token };
  const admin = await getCurrentToken(auth);
  return { secretManager, auth, admin };
};

/** The grant's active tokens. Never the admin token, and only names P0 gave. */
const grantTokens = async (
  auth: GitguardianAuth,
  admin: ApiToken,
  userId: ResourceSchema["UserId"]
) => {
  if (admin.member_id === null) {
    throw new ConnectorError({
      type: "unknown",
      message:
        "The GitGuardian admin token has no member, so P0 can't find its tokens",
      payload: { tokenId: admin.id },
    });
  }
  const prefix = tokenPrefixFor(userId);
  return (await listActiveTokens(auth, admin.member_id)).filter(
    (token) => token.id !== admin.id && token.name.startsWith(prefix)
  );
};

/**
 * Revokes one token. A token that is already gone counts as revoked: an agent
 * can end its own token with the MCP's `revoke_current_token`. GitGuardian
 * answers 404, or 403 with this detail, for one.
 */
const revokeToken = async (
  log: Logger,
  auth: GitguardianAuth,
  tokenId: string
) => {
  try {
    await withRetries(() => deleteToken(auth, tokenId), isRetryable);
    log.info({ tokenId }, "revoked GitGuardian token");
  } catch (error) {
    const status = errorStatus(error);
    if (
      status === 404 ||
      (status === 403 &&
        errorDetail(error) === "This token has already been revoked")
    ) {
      log.info({ tokenId, status }, "GitGuardian token already gone");
      return;
    }
    log.error({ tokenId, status }, "failed to revoke GitGuardian token");
    throw new ConnectorError({
      type: error instanceof ConnectorError ? error.data.type : "unknown",
      message: `P0 couldn't revoke GitGuardian token ${tokenId}${
        status !== undefined ? ` (${status})` : ""
      }. It stays valid until it is revoked or expires.`,
      payload: { tokenId, ...(status !== undefined ? { status } : {}) },
    });
  }
};

const isCapFull = (error: unknown) =>
  errorStatus(error) === 400 &&
  /^The limit of \d+ active .*tokens is reached/.test(
    String(errorDetail(error) ?? "")
  );

/**
 * Gives the grant one token with exactly `scopes`, lasting until its longest
 * open request ends. GitGuardian can't change a token, so every change mints a
 * new token, stores it, and then revokes the old ones. No scopes revokes them.
 */
const setGrantScopes = async (
  log: Logger,
  context: RequestContext,
  userId: ResourceSchema["UserId"],
  policies: ResourceSchema["Policy"][]
) => {
  if (policies.length !== 1) {
    log.error(
      { nPolicies: policies.length },
      "expected exactly 1 policy for GitGuardian token scopes"
    );
    // "unknown" rather than "validation_error": this is a control-plane bug,
    // not a problem with the user's request.
    throw new ConnectorError({
      type: "unknown",
      message:
        "Invalid parameters for GitGuardian token scopes, expected exactly 1 policy",
      payload: { requestId: context.requestId, nPolicies: policies.length },
    });
  }

  const [{ scopes }] = policies;
  const outside = scopes.filter(
    (scope) => !(requestableScopes as readonly string[]).includes(scope)
  );
  if (outside.length > 0) {
    throw refusal(
      `P0 can't grant ${outside.join(", ")}. Request only ${requestableScopes.join(", ")}.`,
      { scopes: outside.join(",") }
    );
  }

  const { secretManager, auth, admin } = await newWorkspaceClients(context);
  const existing = await grantTokens(auth, admin, userId);

  if (scopes.length === 0) {
    for (const token of existing) await revokeToken(log, auth, token.id);
    return;
  }

  const missing = scopes.filter((scope) => !admin.scopes.includes(scope));
  if (missing.length > 0) {
    throw refusal(
      `The admin token for workspace ${context.workspaceId} doesn't hold ${missing.join(", ")}. Ask your P0 admin to recreate it with every scope.`,
      { workspaceId: context.workspaceId, scopes: missing.join(",") }
    );
  }

  const lifetime = lifetimeDays(context.grantEndsAt);
  let token: ApiToken & { key: string };
  try {
    token = await withRetries(
      () =>
        mintToken(auth, {
          name: `${tokenPrefixFor(userId)}${Math.floor(Date.now() / 1000)}`,
          type: admin.type,
          scopes: [...scopes].sort(),
          lifetime,
        }),
      (error) => errorStatus(error) === 409 || isRetryable(error)
    );
  } catch (error) {
    if (isCapFull(error)) {
      throw refusal(
        `GitGuardian workspace ${context.workspaceId} has no free API token slots. Its connector member already holds the most tokens GitGuardian allows. Try again when another grant ends, or ask a GitGuardian admin to revoke unused tokens of that member.`,
        { workspaceId: context.workspaceId }
      );
    }
    throw error;
  }

  try {
    await secretManager.createSecretVersion({
      ref: secretRef(userId),
      type: "value",
      value: Buffer.from(token.key),
    });
  } catch (error) {
    // Revoke the token that this call made, so that a failed grant does not
    // leave a valid token that no secret holds.
    await deleteToken(auth, token.id).catch((revokeError: unknown) =>
      log.error(
        { tokenId: token.id, error: revokeError },
        "failed to revoke the token of a failed grant; it stays valid until revoked or expired"
      )
    );
    throw error;
  }
  // The connector can't return these to P0, so its log is their record.
  log.info(
    {
      tokenId: token.id,
      scopes: token.scopes,
      expireAt: token.expire_at,
      lifetime,
    },
    "minted GitGuardian token and stored it in the secret"
  );

  // The new token is in place, so a failed revoke of an old one doesn't fail
  // the grant. The old token stays valid until it expires.
  for (const old of existing) {
    await revokeToken(log, auth, old.id).catch(() =>
      log.error({ tokenId: old.id }, "old token revoke failed")
    );
  }
};

/**
 * GitGuardian token lifecycle
 *
 * The abstract "user" of the resource-root paradigm is the grant's secret. It
 * holds one token of the admin token's owner, named after the secret. Its
 * policy is the token's scopes.
 *
 * The connector can't read a grant secret back, so it finds a grant's tokens
 * by name. A revoke is what ends access, so every revoke failure propagates.
 *
 * The P0 control plane must serialize calls for the same secret.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) => ({
    validation: () => ({ user: null }),

    getUser: async (context, username) => {
      const logger = ctx.logger.child({
        username,
        requestId: context.requestId,
      });
      const secretManager = await createSecretManager(context.secrets);
      try {
        const { ref } = await secretManager.getSecret({
          ref: secretRef(username),
        });
        return ref;
      } catch (error) {
        // A missing secret means the user does not exist yet; return null so
        // the framework provisions one.
        if (error instanceof SecretNotFoundError) {
          logger.debug("no existing secret found; user will be provisioned");
          return null;
        }
        logger.error({ error }, "failed to look up secret");
        throw error;
      }
    },

    createUser: async (context, username) => {
      const logger = ctx.logger.child({
        username,
        requestId: context.requestId,
      });
      const secretManager = await createSecretManager(context.secrets);
      const secret = await secretManager.createSecret({ name: username });
      logger.info({ secretRef: secret.ref }, "created new secret");
      return secret.ref;
    },

    deleteUser: async (context, userId) => {
      const logger = ctx.logger.child({ userId, requestId: context.requestId });
      const { secretManager, auth, admin } = await newWorkspaceClients(context);
      // Revoke before deleting the secret, so that a failed revoke leaves the
      // secret for the retry.
      for (const token of await grantTokens(auth, admin, userId)) {
        await revokeToken(logger, auth, token.id);
      }
      await secretManager.deleteSecret({ ref: secretRef(userId) });
      logger.info("deleted secret");
    },

    setPoliciesForUser: async (context, userId, _user, policies) => {
      const logger = ctx.logger.child({ userId, requestId: context.requestId });
      await setGrantScopes(logger, context, userId, policies);
    },

    list: async ({ type }) => {
      switch (type) {
        case "scope":
          return requestableScopes.map((scope) => ({
            key: scope,
            value: scope,
          }));
        default:
          throw throwAssertNever(type);
      }
    },
  }));
